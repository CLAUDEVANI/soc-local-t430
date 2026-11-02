#!/usr/bin/env bash
# =============================================================================
# soc_corrigir.sh - automatiza as correções do SOC Local em /opt/soc_local
#
#   sudo ./soc_corrigir.sh                 # DIAGNÓSTICO (não altera nada)
#   sudo ./soc_corrigir.sh --aplicar       # aplica as correções seguras
#   sudo ./soc_corrigir.sh --tudo          # aplicar + venv + git + token + grupo + verificação do tar
#
# Extras (use com --aplicar):
#   --recriar-venv    recria o venv se estiver quebrado (precisa de internet)
#   --limpar-git      recria o repositório .git sem histórico (some o token antigo)
#   --limpar-token    troca o token do Telegram por TOKEN_REVOGADO nos arquivos do projeto
#   --grupo           coloca o usuário que chamou o sudo no grupo do painel (leitura)
#   --verificar-tar   gzip -t e busca de token no backup grande de /home/pereira
#
# Tudo é idempotente. Backups em /root/soc_correcoes_<data>/ . Rollback automático
# do app.py/unit se o painel não responder após o reinício.
# =============================================================================
set -uo pipefail

DST="${DST:-/opt/soc_local}"
UNIT="${UNIT:-soc-dashboard.service}"
SVC_USER="${SVC_USER:-socsvc}"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/soc_local}"
TAR_GLOB="${TAR_GLOB:-/home/pereira/soc_local_backup_*.tar.gz}"
OLD_PATH="${OLD_PATH:-/home/pereira/soc_local}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8501/_stcore/health}"
LOG="${LOG:-/var/log/soc_correcoes.log}"
BK="${BK:-/root/soc_correcoes_$(date +%Y%m%d_%H%M%S)}"
PADRAO_TOKEN='[0-9]{8,10}:AA[0-9A-Za-z_-]{30,}|AAH[0-9A-Za-z_-]{30,}'
QUEM="${SUDO_USER:-gircp}"

APLICAR=0; RECRIAR_VENV=0; LIMPAR_GIT=0; LIMPAR_TOKEN=0; GRUPO=0; VERIF_TAR=0
for a in "$@"; do case "$a" in
  --aplicar) APLICAR=1;; --recriar-venv) RECRIAR_VENV=1;; --limpar-git) LIMPAR_GIT=1;;
  --limpar-token) LIMPAR_TOKEN=1;; --grupo) GRUPO=1;; --verificar-tar) VERIF_TAR=1;;
  --tudo) APLICAR=1; RECRIAR_VENV=1; LIMPAR_GIT=1; LIMPAR_TOKEN=1; GRUPO=1; VERIF_TAR=1;;
  -h|--help) sed -n '2,22p' "$0"; exit 0;;
  *) echo "opção desconhecida: $a"; exit 2;;
esac; done

N_OK=0; N_AJ=0; N_AL=0; N_PEND=0; MUDOU_APP=0; MUDOU_UNIT=0; MUDOU_SERV=0; DROPIN_CRIADO=""
_log() { echo "$(date -Is) $*" >>"$LOG" 2>/dev/null || true; }
ok()   { echo "  [OK]        $*"; N_OK=$((N_OK+1)); _log "OK $*"; }
aj()   { echo "  [AJUSTADO]  $*"; N_AJ=$((N_AJ+1)); _log "AJ $*"; }
pend() { echo "  [PENDENTE]  $*   (use --aplicar)"; N_PEND=$((N_PEND+1)); _log "PEND $*"; }
al()   { echo "  [ALERTA]    $*"; N_AL=$((N_AL+1)); _log "AL $*"; }
inf()  { echo "              $*"; }
sec()  { echo; echo "== $* =="; }
tem()  { command -v "$1" >/dev/null 2>&1; }
imut() { tem lsattr && lsattr -d "$1" 2>/dev/null | awk '{print $1}' | grep -q 'i'; }
sem_imut() { imut "$1" && chattr -i "$1" 2>/dev/null; return 0; }
bk()   { [ -e "$1" ] || return 0; mkdir -p "$BK$(dirname "$1")"; cp -a "$1" "$BK$1"; }

[ "$(id -u)" -eq 0 ] || { echo "execute com sudo"; exit 1; }
[ -d "$DST" ] || { echo "pasta não encontrada: $DST"; exit 1; }
[ "$APLICAR" = 1 ] && mkdir -p "$BK" && chmod 700 "$BK"
echo "Modo: $([ "$APLICAR" = 1 ] && echo "APLICAR (backups em $BK)" || echo "DIAGNÓSTICO (nada será alterado)")"

GRP="$SVC_USER"; getent group "$SVC_USER" >/dev/null || GRP=root

# ---------------------------------------------------------------- 1. serviço
sec "1. Serviço"
UNIT_USER=""; EXEC_ATUAL=""
if tem systemctl; then
  UNIT_USER="$(systemctl show -p User --value "$UNIT" 2>/dev/null || true)"
  EXEC_ATUAL="$(systemctl cat "$UNIT" 2>/dev/null | grep -E '^ExecStart=' | tail -1 || true)"
  if systemctl is-active --quiet "$UNIT"; then ok "$UNIT ativo (usuário: ${UNIT_USER:-root})"; else al "$UNIT NÃO está ativo"; fi
else al "systemctl indisponível"; fi
[ -n "$EXEC_ATUAL" ] && inf "$EXEC_ATUAL" | cut -c1-150
SERV_NAO_ROOT=0; [ -n "$UNIT_USER" ] && [ "$UNIT_USER" != "root" ] && SERV_NAO_ROOT=1

# --------------------------------------------------------------- 2. app.py
sec "2. app.py"
APP="$DST/app.py"
if [ ! -f "$APP" ]; then al "$APP inexistente"; else
  inf "sha256 atual: $(sha256sum "$APP" | cut -c1-16)…"
  TMP="$(mktemp)"
  python3 - "$APP" "$TMP" "$([ "$SERV_NAO_ROOT" = 1 ] && echo nao-root || echo root)" <<'PY'
import re, sys, ast
src, dst, modo = sys.argv[1:4]
s = open(src, encoding="utf-8").read()
mud = []

def troca(velho, novo, rotulo):
    global s
    if velho in s:
        s = s.replace(velho, novo); mud.append(rotulo)

# 1) imports/constantes sem uso
if re.search(r'^import json\n', s, re.M) and 'json.' not in s:
    s = re.sub(r'^import json\n', '', s, count=1, flags=re.M); mud.append("remove import json sem uso")
if re.search(r'^import sqlite3\n', s, re.M) and 'sqlite3.' not in s:
    s = re.sub(r'^import sqlite3\n', '', s, count=1, flags=re.M); mud.append("remove import sqlite3 sem uso")
if len(re.findall(r'\bDB_PATH\b', s)) == 1:
    s = re.sub(r'^DB_PATH = .*\n', '', s, count=1, flags=re.M); mud.append("remove DB_PATH sem uso")

# 2) Suricata: o parser é de fast.log; eve.json só com o parser novo (v3)
parser_fast = "'->' not in linha" in s and 'json.loads' not in s
if parser_fast:
    if re.search(r'^LOG_SURICATA = "[^"]*eve\.json"', s, re.M):
        s = re.sub(r'^LOG_SURICATA = "[^"]*eve\.json"', 'LOG_SURICATA = "/var/log/suricata/fast.log"', s, count=1, flags=re.M)
        mud.append("LOG_SURICATA: eve.json -> fast.log (o parser lê fast.log)")
    troca('"O que ocorreu?", "Severidade"]', '"O que ocorreu?", "Medida"]', 'colunas do Suricata: Severidade -> Medida')

# 3) IP do cliente com a API atual (módulo websocket_headers não existe mais)
NOVO = '''def _ip_cliente():
    """IP do cliente. X-Forwarded-For só vale atrás do SEU proxy (defina SOC_TRUST_PROXY=1)."""
    try:
        ip = st.context.ip_address or ""
        if os.environ.get("SOC_TRUST_PROXY") == "1":
            xff = st.context.headers.get("X-Forwarded-For", "")
            if xff:
                ip = xff.split(",")[0].strip()
        return str(ipaddress.ip_address(ip))   # só aceita IP válido (sem quebra de linha/injeção)
    except Exception:
        return "desconhecido"


def _log_auth(msg):
    print(f"[SOC-AUTH] {datetime.datetime.now().isoformat(timespec='seconds')} ip={_ip_cliente()} {msg}", flush=True)'''
if 'def _ip_cliente' not in s:
    m = re.search(r'def _log_auth\(msg\):.*?(?=\n\n+def |\n\n+# |\Z)', s, re.S)
    if m:
        s = s[:m.start()] + NOVO + s[m.end():]; mud.append("_log_auth: IP do cliente via st.context (validado)")
        if not re.search(r'^import ipaddress\n', s, re.M):
            s = s.replace("import os\n", "import os\nimport ipaddress\n", 1); mud.append("adiciona import ipaddress")

# 4) caminhos antigos e execução do EDR
if '/home/pereira/soc_local' in s:
    s = s.replace('/home/pereira/soc_local', '/opt/soc_local'); mud.append("caminho antigo /home/pereira/soc_local -> /opt/soc_local")
if modo == "nao-root":
    troca("subprocess.run([SCRIPT_EDR], check=True, timeout=30)",
          "subprocess.run(['sudo', SCRIPT_EDR], check=True, timeout=60)", "EDR via sudo (painel não roda como root)")
    for nome in ("LOG_SURICATA", "LOG_NGINX"):
        troca(f"if os.path.exists({nome}):",
              "if True:  # leitura via sudo tail (o usuário do painel pode não atravessar /var/log)",
              f"{nome}: não depender de os.path.exists (permissão de diretório)")

ast.parse(s)                                   # só grava se a sintaxe for válida
open(dst, "w", encoding="utf-8").write(s)
print("\n".join(mud)); sys.exit(0 if mud else 10)
PY
  rc=$?
  if [ $rc -eq 10 ]; then ok "app.py já está correto (nada a mudar)"
  elif [ $rc -ne 0 ]; then al "falha ao analisar app.py (sintaxe inválida ou erro) - nada foi alterado"
  else
    while IFS= read -r l; do [ -n "$l" ] && inf "• $l"; done < <(python3 - "$APP" "$TMP" <<'PY'
import difflib,sys
a=open(sys.argv[1],encoding='utf-8').read().splitlines(); b=open(sys.argv[2],encoding='utf-8').read().splitlines()
print(f"{sum(1 for l in difflib.ndiff(a,b) if l[:2] in ('+ ','- '))} linhas alteradas")
PY
)
    if [ "$APLICAR" = 1 ]; then
      bk "$APP"; sem_imut "$APP"
      install -m 640 -o root -g "$GRP" "$TMP" "$APP" && { aj "app.py corrigido (backup: $BK$APP)"; MUDOU_APP=1; MUDOU_SERV=1; }
    else pend "app.py tem correções a aplicar (veja as linhas acima)"; fi
  fi
  rm -f "$TMP"
fi

# -------------------------------------------------------------- 3. permissões
sec "3. Permissões em $DST"
perm() {  # perm ARQUIVO DONO:GRUPO MODO
  [ -e "$1" ] || return 0
  atual="$(stat -c '%U:%G %a' "$1")"
  if [ "$atual" = "$2 $3" ]; then ok "$(basename "$1") $atual"; return 0; fi
  if [ "$APLICAR" = 1 ]; then sem_imut "$1"; chown "$2" "$1" && chmod "$3" "$1" && aj "$(basename "$1"): $atual -> $2 $3"
  else pend "$(basename "$1"): $atual (esperado $2 $3)"; fi
}
for f in .gitignore README.md requirements.txt; do perm "$DST/$f" "root:$GRP" 644; done
perm "$DST/app.py" "root:$GRP" 640
for f in app.py.save app_estavel.py.bak nohup.out ips_alertados.txt; do perm "$DST/$f" root:root 600; done
for d in .git backup backups; do
  [ -d "$DST/$d" ] || continue
  if [ -n "$(find "$DST/$d" \( -perm /077 -o ! -user root \) -print -quit 2>/dev/null)" ]; then
    if [ "$APLICAR" = 1 ]; then find "$DST/$d" -exec chattr -i {} + 2>/dev/null; chown -R root:root "$DST/$d"; chmod -R go-rwx "$DST/$d"; aj "$d/ fechado (root:root, sem acesso a outros)"
    else pend "$d/ legível por outros usuários"; fi
  else ok "$d/ restrito ao root"; fi
done
RUINS="$(find "$DST" -path "$DST/venv" -prune -o -path "$DST/.git" -prune -o \( -perm -g+w -o -perm -o+w -o -user "$SVC_USER" \) -print 2>/dev/null)"
if [ -z "$RUINS" ]; then ok "nenhum arquivo gravável por grupo/outros nem do usuário $SVC_USER"
elif [ "$APLICAR" = 1 ]; then
  while IFS= read -r f; do sem_imut "$f"; chown root:"$GRP" "$f"; chmod g-w,o-w "$f"; done <<<"$RUINS"
  aj "removida escrita de grupo/outros em $(echo "$RUINS" | wc -l) item(ns)"
else pend "$(echo "$RUINS" | wc -l) item(ns) graváveis por grupo/outros"; fi

# ----------------------------------------------------------------- 4. venv
sec "4. venv"
V="$DST/venv"; QUEBRADO=0; MOTIVO=""
if [ ! -x "$V/bin/python3" ]; then QUEBRADO=1; MOTIVO="venv ausente"
else
  head -1 "$V/bin/streamlit" 2>/dev/null | grep -q "$OLD_PATH" && { QUEBRADO=1; MOTIVO="shebang do streamlit aponta para $OLD_PATH"; }
  grep -qE "^(home|executable|command) *=.*$OLD_PATH" "$V/pyvenv.cfg" 2>/dev/null && { QUEBRADO=1; MOTIVO="pyvenv.cfg aponta para $OLD_PATH"; }
  "$V/bin/python3" -c 'import streamlit, pyotp, geoip2, streamlit_autorefresh, psutil, pandas' 2>/dev/null \
    || { QUEBRADO=1; MOTIVO="${MOTIVO:-dependências não importam}"; }
fi
if [ $QUEBRADO = 0 ]; then ok "venv íntegro"
elif [ "$APLICAR" = 1 ] && [ "$RECRIAR_VENV" = 1 ]; then
  PY="$(readlink -f "$V/bin/python3" 2>/dev/null)"; [ -x "$PY" ] || PY="$(command -v python3)"
  mkdir -p "$BK"; mv "$V" "$BK/venv_antigo"
  if "$PY" -m venv "$V" && "$V/bin/pip" install -q -r "$DST/requirements.txt" \
     && "$V/bin/python3" -c 'import streamlit, pyotp, geoip2, streamlit_autorefresh, psutil, pandas'; then
    chown -R root:root "$V"; aj "venv recriado ($MOTIVO); antigo em $BK/venv_antigo"; MUDOU_SERV=1
  else rm -rf "$V"; mv "$BK/venv_antigo" "$V"; al "falha ao recriar o venv - o antigo foi restaurado"; fi
elif [ "$APLICAR" = 1 ]; then al "venv quebrado ($MOTIVO) - rode com --recriar-venv"
else pend "venv quebrado: $MOTIVO (use --recriar-venv)"; fi

# ------------------------------------------------- 5. caminho da unit systemd
sec "5. Caminho do ExecStart"
if [ -n "$EXEC_ATUAL" ]; then
  if grep -q "$OLD_PATH" <<<"$EXEC_ATUAL"; then
    NOVO_EXEC="${EXEC_ATUAL//$OLD_PATH//opt/soc_local}"
    if [ "$APLICAR" = 1 ]; then
      D="/etc/systemd/system/$UNIT.d"; mkdir -p "$D"; bk "$D/10-caminho.conf"
      printf '[Service]\nExecStart=\n%s\nWorkingDirectory=%s\n' "$NOVO_EXEC" "$DST" >"$D/10-caminho.conf"
      DROPIN_CRIADO="$D/10-caminho.conf"; aj "ExecStart agora aponta para $DST (drop-in 10-caminho.conf)"; MUDOU_UNIT=1; MUDOU_SERV=1
    else pend "ExecStart ainda usa $OLD_PATH"; fi
  else ok "ExecStart não usa o caminho antigo"; fi
else inf "(sem ExecStart para verificar)"; fi

# ------------------------------------------------------------ 6. sudoers
sec "6. sudoers do painel (usuário: ${UNIT_USER:-root})"
if [ "$SERV_NAO_ROOT" = 1 ]; then
  T="/usr/bin/tail"; C="/usr/bin/cat"; F="/usr/bin/fail2ban-client"
  WANT="$(mktemp)"
  cat >"$WANT" <<SUD
# Gerado por soc_corrigir.sh - o painel só roda estes comandos, sem curingas.
Defaults:$UNIT_USER !requiretty, !lecture, env_reset
$UNIT_USER ALL=(root) NOPASSWD: \\
  $T -n 100 /var/log/suricata/fast.log, \\
  $T -n 2000 /var/log/suricata/eve.json, \\
  $T -n 50 /var/log/nginx/access.log, \\
  $F status suricata, \\
  $F status sshd, \\
  $F status nginx-botsearch, \\
  $C /var/log/shadow_ai_edr.log, \\
  $DST/edr_shadow_ai.sh
SUD
  if tem visudo && ! visudo -cf "$WANT" >/dev/null 2>&1; then al "sudoers gerado é inválido - não instalado"
  elif [ -f "$SUDOERS_FILE" ] && cmp -s "$WANT" "$SUDOERS_FILE"; then ok "$SUDOERS_FILE já correto"
  elif [ "$APLICAR" = 1 ]; then bk "$SUDOERS_FILE"; install -m 440 -o root -g root "$WANT" "$SUDOERS_FILE" && aj "$SUDOERS_FILE gravado (comandos exatos)"
  else pend "sudoers do painel ausente/diferente"; fi
  rm -f "$WANT"
else inf "serviço roda como root: sudoers dedicado não é necessário"; fi

# ----------------------------------------------- 7. token e histórico do git
sec "7. Token do Telegram"
mapfile -t ACH < <(grep -rIlE "$PADRAO_TOKEN" "$DST" --exclude-dir=venv --exclude-dir=.git 2>/dev/null || true)
if [ "${#ACH[@]}" -eq 0 ]; then ok "nenhum token em texto nos arquivos do projeto"
else
  for f in "${ACH[@]}"; do
    if [ "$APLICAR" = 1 ] && [ "$LIMPAR_TOKEN" = 1 ]; then bk "$f"; sem_imut "$f"; sed -i -E "s/$PADRAO_TOKEN/TOKEN_REVOGADO/g" "$f"; aj "token removido de $(basename "$f")"
    else al "token em $(basename "$f") (use --limpar-token)"; fi
  done
fi
if [ -d "$DST/.git" ] && tem git; then
  N="$(git -C "$DST" log --all -p 2>/dev/null | grep -cE "$PADRAO_TOKEN" || true)"
  if [ "${N:-0}" -gt 0 ]; then
    if [ "$APLICAR" = 1 ] && [ "$LIMPAR_GIT" = 1 ]; then
      mv "$DST/.git" "/root/git_antigo_$(date +%Y%m%d_%H%M%S)"
      git -C "$DST" init -q && git -C "$DST" add -A >/dev/null 2>&1 \
        && git -C "$DST" -c user.name=soc -c user.email=soc@localhost commit -qm "baseline limpo" >/dev/null 2>&1
      chmod -R go-rwx "$DST/.git"; aj "repositório recriado sem histórico (o antigo ficou em /root/git_antigo_*)"
    else al "histórico do git contém o token em $N linha(s) (--limpar-git recria o repositório). REVOGUE o token no @BotFather."; fi
  else ok "histórico do git sem token"; fi
fi

# --------------------------------------------------------------- 8. backups
sec "8. Backup compactado em /home/pereira"
shopt -s nullglob; TARS=($TAR_GLOB); shopt -u nullglob
if [ "${#TARS[@]}" -eq 0 ]; then inf "(nenhum $TAR_GLOB)"; fi
for t in "${TARS[@]}"; do
  if [ "$(stat -c '%a %U' "$t")" = "600 root" ]; then ok "$(basename "$t") restrito (600 root)"
  elif [ "$APLICAR" = 1 ]; then sem_imut "$t"; chown root:root "$t"; chmod 600 "$t"; aj "$(basename "$t") -> 600 root:root"
  else pend "$(basename "$t") legível por outros usuários"; fi
  if [ "$VERIF_TAR" = 1 ]; then
    inf "verificando $(basename "$t") (pode levar alguns minutos)…"
    if gzip -t "$t" 2>/dev/null; then ok "gzip íntegro"; else al "gzip CORROMPIDO: $t"; fi
    tar -xzOf "$t" 2>/dev/null | grep -aEq "$PADRAO_TOKEN" && al "token presente DENTRO do backup (guarde-o cifrado/offline ou recrie)" || ok "sem token dentro do backup"
  fi
done

# ----------------------------------------------------------------- 9. grupo
sec "9. Acesso de leitura para $QUEM"
if id -nG "$QUEM" 2>/dev/null | tr ' ' '\n' | grep -qx "$GRP"; then ok "$QUEM já está no grupo $GRP"
elif [ "$GRUPO" = 1 ] && [ "$APLICAR" = 1 ]; then usermod -aG "$GRP" "$QUEM" && aj "$QUEM adicionado ao grupo $GRP (saia e entre na sessão, ou use 'newgrp $GRP')"
else pend "$QUEM fora do grupo $GRP (opção --grupo): sem isso só lê com sudo"; fi
id -nG "$QUEM" 2>/dev/null | tr ' ' '\n' | grep -qx lxd && al "$QUEM está no grupo lxd (equivale a root sem senha). Remova: sudo gpasswd -d $QUEM lxd"

# ----------------------------------------------------- 10. referências antigas
sec "10. Referências ao caminho antigo ($OLD_PATH)"
REF="$(grep -rIl "$OLD_PATH" /etc/cron* /var/spool/cron /etc/systemd/system "$DST"/*.sh 2>/dev/null | grep -v "^$BK" | grep -v '/10-caminho.conf' || true)"
if [ -z "$REF" ]; then ok "nada aponta para o caminho antigo"
else al "ainda referenciam $OLD_PATH (ajuste manualmente):"; echo "$REF" | sed 's/^/              /'; fi

# ------------------------------------------------- 11. reinício + health check
sec "11. Reinício e verificação"
if [ "$APLICAR" = 1 ] && [ "$MUDOU_SERV" = 1 ] && tem systemctl; then
  [ "$MUDOU_UNIT" = 1 ] && systemctl daemon-reload
  systemctl restart "$UNIT"
  UP=0; for _ in $(seq 1 30); do sleep 1; curl -sf --max-time 3 "$HEALTH_URL" 2>/dev/null | grep -q ok && { UP=1; break; }; done
  if [ $UP = 1 ]; then aj "painel respondeu após o reinício"
  else
    al "painel NÃO respondeu - revertendo app.py e drop-in"
    [ "$MUDOU_APP" = 1 ] && [ -f "$BK$APP" ] && install -m 640 -o root -g "$GRP" "$BK$APP" "$APP"
    [ -n "$DROPIN_CRIADO" ] && rm -f "$DROPIN_CRIADO"
    systemctl daemon-reload; systemctl restart "$UNIT"
    journalctl -u "$UNIT" -n 12 --no-pager 2>/dev/null | grep -v 'pam_unix\|sudo\[' | sed 's/^/              /'
  fi
elif [ "$APLICAR" = 1 ]; then ok "nenhuma mudança exigiu reiniciar o painel"
else inf "(diagnóstico: sem reinício)"; fi

# ------------------------------------------------------------- relatório
sec "Resumo"
echo "  OK: $N_OK   AJUSTADOS: $N_AJ   PENDENTES: $N_PEND   ALERTAS: $N_AL"
[ "$APLICAR" = 1 ] && echo "  Backups: $BK   |   Log: $LOG"
[ "$N_PEND" -gt 0 ] && echo "  Há itens PENDENTES: rode com --aplicar (ou --tudo)."
echo "  Ações que só você pode fazer: revogar o token no @BotFather (/revoke) e conferir os crontabs listados na seção 10."
[ "$APLICAR" = 1 ] && echo "  Desfazer o app.py: sudo install -m 640 -o root -g $GRP $BK$APP $APP && sudo systemctl restart $UNIT"
exit 0
