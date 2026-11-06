import streamlit as st
import pandas as pd
import psutil
import subprocess
import datetime
import os
import stat
import hmac
import ipaddress
import re
import threading
import geoip2.database
import time
import pyotp

# ==========================================
# CONFIGURAÇÕES DA PÁGINA
# ==========================================
st.set_page_config(page_title="SOC Local - T430", layout="wide")

# ==========================================
# AUTENTICAÇÃO (Senha + 2FA TOTP) - fail-closed
# ==========================================
SENHA_PAINEL = os.environ.get("SOC_PASSWORD", "")
TOTP_SECRET = os.environ.get("SOC_TOTP_SECRET", "")
SEGREDOS_PROIBIDOS = {"JBSWY3DPEHPK3PXP"}
SESSAO_MAX_SEGUNDOS = 8 * 3600
MAX_FALHAS = 5
BLOQUEIO_SEGUNDOS = 300

if not SENHA_PAINEL or len(TOTP_SECRET) < 16 or TOTP_SECRET in SEGREDOS_PROIBIDOS:
    st.error("Autenticação não configurada corretamente. Painel bloqueado.")
    st.stop()


@st.cache_resource
def _estado_login():
    return {
        "lock": threading.Lock(),
        "ips": {},
        "ultimo_passo": 0
    }


def _ip_cliente():
    try:
        ip = st.context.ip_address or ""
        if os.environ.get("SOC_TRUST_PROXY") == "1":
            xff = st.context.headers.get("X-Forwarded-For", "")
            if xff:
                ip = xff.split(",")[0].strip()
        return str(ipaddress.ip_address(ip))
    except Exception:
        return "desconhecido"


def _log_auth(msg):
    msg_limpa = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', str(msg))[:200]
    print(f"[SOC-AUTH] {datetime.datetime.now().isoformat(timespec='seconds')} ip={_ip_cliente()} {msg_limpa}", flush=True)


def _checar_bloqueio_ip(ip):
    estado = _estado_login()
    with estado["lock"]:
        dados_ip = estado["ips"].get(ip, {"falhas": 0, "bloqueado_ate": 0.0})
        return time.time() < dados_ip["bloqueado_ate"]


def _registrar_falha(motivo):
    ip = _ip_cliente()
    estado = _estado_login()
    with estado["lock"]:
        if len(estado["ips"]) > 1000:
            agora = time.time()
            estado["ips"] = {k: v for k, v in estado["ips"].items() if agora < v["bloqueado_ate"]}
            if len(estado["ips"]) > 1000:
                estado["ips"].clear()
        dados_ip = estado["ips"].setdefault(ip, {"falhas": 0, "bloqueado_ate": 0.0})
        dados_ip["falhas"] += 1
        tentativas = dados_ip["falhas"]
        if tentativas >= MAX_FALHAS:
            dados_ip["bloqueado_ate"] = time.time() + BLOQUEIO_SEGUNDOS
            dados_ip["falhas"] = 0
            bloqueado = True
        else:
            bloqueado = False
    _log_auth(f"falha de login ({motivo}); tentativas={tentativas}")
    if bloqueado:
        _log_auth(f"login bloqueado por {BLOQUEIO_SEGUNDOS}s")


def _limpar_falhas_ip():
    ip = _ip_cliente()
    estado = _estado_login()
    with estado["lock"]:
        estado["ips"].pop(ip, None)


def _verificar_totp(codigo):
    if not (codigo.isdigit() and len(codigo) == 6):
        return False
    totp = pyotp.TOTP(TOTP_SECRET)
    agora = time.time()
    passo_atual = int(agora // totp.interval)
    estado = _estado_login()
    with estado["lock"]:
        for desloc in (-1, 0, 1):
            if hmac.compare_digest(totp.at(agora, desloc), codigo):
                passo = passo_atual + desloc
                if passo <= estado["ultimo_passo"]:
                    return False
                estado["ultimo_passo"] = passo
                return True
    return False


if st.session_state.get("autenticado") and \
        time.time() - st.session_state.get("auth_ts", 0) > SESSAO_MAX_SEGUNDOS:
    st.session_state.clear()
    st.warning("Sessão expirada. Autentique-se novamente.")

if not st.session_state.get("autenticado"):
    if _checar_bloqueio_ip(_ip_cliente()):
        st.error("Muitas tentativas a partir do seu IP. Aguarde alguns minutos.")
        st.stop()
    if not st.session_state.get("senha_ok"):
        st.title("🔒 SOC Local - Acesso Restrito (Passo 1/2)")
        senha = st.text_input("Senha", type="password")
        if senha:
            if hmac.compare_digest(senha.encode("utf-8"), SENHA_PAINEL.encode("utf-8")):
                st.session_state["senha_ok"] = True
                st.rerun()
            else:
                _registrar_falha("senha")
                st.error("Credenciais inválidas.")
        st.stop()
    st.title("📱 SOC Local - Autenticação 2FA (Passo 2/2)")
    codigo = st.text_input("Código de 6 dígitos do Google Authenticator", max_chars=6)
    if codigo:
        if _verificar_totp(codigo):
            _limpar_falhas_ip()
            st.session_state["autenticado"] = True
            st.session_state["auth_ts"] = time.time()
            st.session_state.pop("senha_ok", None)
            _log_auth("login bem-sucedido")
            st.rerun()
        else:
            _registrar_falha("totp")
            st.error("Credenciais inválidas.")
    st.stop()

# ==========================================
# CONSTANTES E CAMINHOS ABSOLUTOS
# ==========================================
GEOIP_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
JAILS_FAIL2BAN = ["endlessh", "nginx-botsearch", "recidive", "soc-auth", "sshd", "suricata", "ufw-honeypot"]
LOG_SURICATA = "/var/log/suricata/fast.log"
LOG_NGINX = "/var/log/nginx/access.log"
SCRIPT_EDR = "/opt/soc_local/edr_shadow_ai.sh"
LOG_EDR = "/var/log/shadow_ai_edr.log"

COLUNAS_SURICATA = ["Data/Hora", "Origem (IP)", "Destino (IP)", "Localização Externa", "O que ocorreu?", "Prioridade", "Medida"]
COLUNAS_F2B = ["Origem (IP)", "Localização", "Estado", "Prisão"]
COLUNAS_NGINX = ["Data/Hora", "Origem (IP)", "Método", "Rota Acedida", "Status"]

PADRAO_NGINX = re.compile(r'^(\S+) \S+ \S+ \[(.*?)\] "(?:(\S+) )?(.*?)(?: HTTP/\d\.\d)?" (\d+)')
CHARS_CONTROLE = re.compile(r'[\x00-\x1f\x7f-\x9f]')

RUIDO_SURICATA = (
    "STUN Binding",
    "UDPv6 invalid checksum",
    "Packet with invalid timestamp",
    "excessive retransmissions",
    "SYNACK resend with different seq",
    "SURICATA STREAM"
)


def _sanitizar_celula(texto, max_len=220):
    if not texto:
        return ""
    limpo = CHARS_CONTROLE.sub(" ", str(texto)).strip()
    return limpo[:max_len] + ("…" if len(limpo) > max_len else "")


def _arquivo_seguro_root(caminho):
    try:
        st_info = os.lstat(caminho)
        if stat.S_ISLNK(st_info.st_mode) or not stat.S_ISREG(st_info.st_mode):
            return False, "Arquivo é um link simbólico ou não é arquivo regular."
        if st_info.st_uid != 0:
            return False, "Arquivo não pertence ao root (UID != 0)."
        if st_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False, "Permissões inseguras: grupo ou outros têm permissão de escrita."
        return True, "OK"
    except Exception as e:
        return False, str(e)


def executar(comando, timeout=5):
    try:
        resultado = subprocess.run(
            comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=timeout, check=False
        )
        return resultado.stdout
    except Exception:
        return ""


@st.cache_resource
def _leitor_geoip():
    return geoip2.database.Reader(GEOIP_DB)


def obter_localizacao(ip):
    try:
        endereco = ipaddress.ip_address(ip)
        if not endereco.is_global:
            return "Rede Local"
        resposta = _leitor_geoip().city(ip)
        cidade = resposta.city.name or "Desconhecido"
        pais = resposta.country.name or "Desconhecido"
        return _sanitizar_celula(f"{cidade}, {pais}", 80)
    except Exception:
        return "Desconhecido"


def verificar_servico(nome_servico):
    return executar(['/usr/bin/systemctl', 'is-active', nome_servico]).strip() == 'active'


def alertas_recentes(df, minutos=60):
    if df.empty:
        return 0
    agora = datetime.datetime.now()
    total = 0
    for marca, prio in zip(df["Data/Hora"], df["Prioridade"]):
        if prio > 2:
            continue
        try:
            momento = datetime.datetime.strptime(marca, "%m/%d/%Y-%H:%M:%S")
            if 0 <= (agora - momento).total_seconds() <= minutos * 60:
                total += 1
        except ValueError:
            continue
    return total


def _ultimas_linhas(caminho, n=100, bloco=65536, max_bytes=4 * 1024 * 1024):
    with open(caminho, "rb") as f:
        f.seek(0, os.SEEK_END)
        tam = f.tell()
        if tam == 0:
            return []
        lido = min(bloco, tam)
        while True:
            f.seek(max(0, tam - lido))
            dados = f.read(lido)
            if dados.count(b"\n") > n or lido >= tam or lido >= max_bytes:
                break
            lido = min(lido * 2, tam, max_bytes)
    return dados.decode("utf-8", errors="replace").splitlines()[-n:]


def _limpar_ip_porta(texto):
    texto = texto.strip().replace('[', '').replace(']', '')
    if texto.count(':') == 1 or (texto.count('.') == 3 and ':' in texto):
        candidato = re.sub(r':\d+$', '', texto)
        try:
            return str(ipaddress.ip_address(candidato))
        except ValueError:
            return _sanitizar_celula(candidato, 45)
    partes = texto.rsplit(':', 1)
    if len(partes) == 2 and partes[1].isdigit():
        try:
            return str(ipaddress.ip_address(partes[0]))
        except ValueError:
            pass
    return _sanitizar_celula(texto, 45)


@st.cache_data(ttl=5)
def ler_log_suricata(ocultar_ruido=True, ocultar_ip_proprio=True):
    dados = []
    ips_ignorados = {"192.168.15.3"}
    if ocultar_ip_proprio:
        ips_ignorados.add("192.168.15.8")
    try:
        linhas = _ultimas_linhas(LOG_SURICATA, 1500)
        for linha in reversed(linhas):
            if not linha or '->' not in linha:
                continue
            try:
                partes_seta = linha.split('->')
                data_hora = _sanitizar_celula(partes_seta[0].split()[0].split('.')[0], 30)
                origem = _limpar_ip_porta(partes_seta[0].split()[-1])
                destino = _limpar_ip_porta(partes_seta[1].split()[0])
                if origem in ips_ignorados:
                    continue
                m = re.search(r'\[\*\*\]\s*\[[\d:]+\]\s*(.*?)\s*\[\*\*\]', linha)
                descricao = _sanitizar_celula(m.group(1) if m else "Atividade suspeita detetada.", 180)
                p = re.search(r'\[Priority:\s*(\d+)\]', linha)
                prioridade = int(p.group(1)) if p else 3
                if ocultar_ruido and any(r in descricao for r in RUIDO_SURICATA):
                    continue
                loc_origem = obter_localizacao(origem)
                loc_exibida = obter_localizacao(destino) if loc_origem == "Rede Local" else loc_origem
                dados.append({
                    "Data/Hora": data_hora,
                    "Origem (IP)": origem,
                    "Destino (IP)": destino,
                    "Localização Externa": loc_exibida,
                    "O que ocorreu?": descricao,
                    "Prioridade": prioridade,
                    "Medida": "🚨 Investigar" if prioridade <= 2 else "⚠️ Monitorizando"
                })
            except Exception:
                continue
    except Exception:
        pass
    if not dados:
        return pd.DataFrame(columns=COLUNAS_SURICATA)
    df = pd.DataFrame(dados)
    df = df.drop_duplicates(subset=["Data/Hora", "Origem (IP)", "Destino (IP)", "O que ocorreu?"])
    return df.sort_values("Prioridade", kind="stable").head(300)


@st.cache_data(ttl=5)
def ler_dados_fail2ban():
    dados_f2b = []
    for jail in JAILS_FAIL2BAN:
        texto = executar(['/usr/bin/fail2ban-client', 'status', jail])
        m = re.search(r'Banned IP list:\s*(.*)', texto)
        ips = m.group(1).split() if m and m.group(1).strip() else []
        for ip in ips:
            try:
                ip_valido = str(ipaddress.ip_address(ip.strip()))
            except ValueError:
                continue
            dados_f2b.append({
                "Origem (IP)": ip_valido,
                "Localização": obter_localizacao(ip_valido),
                "Estado": "🔒 Bloqueado",
                "Prisão": jail
            })
    if not dados_f2b:
        return 0, pd.DataFrame(columns=COLUNAS_F2B)
    df = pd.DataFrame(dados_f2b)
    return int(df["Origem (IP)"].nunique()), df


@st.cache_data(ttl=5)
def ler_log_nginx():
    dados = []
    try:
        linhas = _ultimas_linhas(LOG_NGINX, 50)
    except Exception:
        linhas = []
    for linha in reversed(linhas):
        if not linha:
            continue
        m = PADRAO_NGINX.match(linha)
        if not m:
            continue
        ip, data_hora, metodo, rota, status = m.groups()
        dados.append({
            "Data/Hora": _sanitizar_celula(data_hora, 32),
            "Origem (IP)": _sanitizar_celula(ip, 45),
            "Método": _sanitizar_celula(metodo or "GET", 12),
            "Rota Acedida": _sanitizar_celula(rota or "/", 160),
            "Status": _sanitizar_celula(status or "200", 6)
        })
    return pd.DataFrame(dados) if dados else pd.DataFrame(columns=COLUNAS_NGINX)


FONTES_LOG = [
    ("Suricata - fast.log", LOG_SURICATA),
    ("Suricata - eve.json", "/var/log/suricata/eve.json"),
    ("Nginx - access.log", LOG_NGINX),
    ("Nginx - error.log", "/var/log/nginx/error.log"),
    ("Fail2Ban - fail2ban.log", "/var/log/fail2ban.log"),
    ("UFW - ufw.log", "/var/log/ufw.log"),
    ("SSH/sistema - auth.log", "/var/log/auth.log"),
    ("EDR Shadow AI", LOG_EDR),
]
SERVICOS_EXTRA = ["fail2ban", "suricata", "nginx", "ssh", "ufw", "endlessh"]


def _cmd(comando, timeout=5):
    try:
        r = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 127, "", str(e)


def _idade(seg):
    seg = max(0, int(seg))
    if seg < 90:
        return f"{seg}s"
    if seg < 5400:
        return f"{seg // 60} min"
    if seg < 129600:
        return f"{seg // 3600} h"
    return f"{seg // 86400} d"


@st.cache_data(ttl=10)
def fontes_de_log():
    linhas = []
    agora = time.time()
    for nome, caminho in FONTES_LOG:
        try:
            info = os.stat(caminho)
        except FileNotFoundError:
            linhas.append(("Log", nome, caminho, "⚪ não existe", "-", "")); continue
        except PermissionError:
            linhas.append(("Log", nome, caminho, "🔴 sem permissão (pasta)", "-", "o usuário do painel não atravessa o diretório")); continue
        except OSError as e:
            linhas.append(("Log", nome, caminho, "🔴 erro", "-", _sanitizar_celula(e, 80))); continue
        if not os.access(caminho, os.R_OK):
            linhas.append(("Log", nome, caminho, "🔴 sem permissão de leitura", _idade(agora - info.st_mtime), "ajuste grupo/ACL ou reinicie o painel")); continue
        try:
            ultima = (_ultimas_linhas(caminho, 1, bloco=8192, max_bytes=65536) or [""])[0].strip()
            linhas.append(("Log", nome, caminho, "🟢 lido", _idade(agora - info.st_mtime), _sanitizar_celula(ultima, 90)))
        except Exception as e:
            linhas.append(("Log", nome, caminho, "🔴 erro de leitura", _idade(agora - info.st_mtime), _sanitizar_celula(e, 80)))

    rc, out, err = _cmd(["/usr/bin/fail2ban-client", "status"])
    jails_reais = []
    if rc == 0:
        m = re.search(r"Jail list:\s*(.*)", out)
        jails_reais = [j.strip() for j in m.group(1).split(",")] if m else []

    for jail in JAILS_FAIL2BAN:
        rc, out, err = _cmd(["/usr/bin/fail2ban-client", "status", jail])
        txt = (out + " " + err)
        if rc == 0:
            def n(rotulo):
                mm = re.search(rotulo + r":\s*(\d+)", out)
                return mm.group(1) if mm else "?"
            linhas.append(("Jail", jail, "fail2ban-client", "🟢 ativo", "-",
                           f"banidos agora: {n('Currently banned')} | total: {n('Total banned')} | falhas agora: {n('Currently failed')}"))
        elif "ermission denied" in txt or "must be root" in txt or "Errno 13" in txt:
            linhas.append(("Jail", jail, "fail2ban-client", "🔴 sem permissão", "-", "socket do fail2ban restrito ou sessão precisa ser reiniciada"))
        elif "does not exist" in txt or "Sorry but the jail" in txt:
            linhas.append(("Jail", jail, "fail2ban-client", "⚪ jail inexistente", "-", "está na lista do painel mas não no fail2ban"))
        elif rc == 127:
            linhas.append(("Jail", jail, "fail2ban-client", "🔴 comando indisponível", "-", _sanitizar_celula(err, 80)))
        else:
            linhas.append(("Jail", jail, "fail2ban-client", "🔴 erro", "-", _sanitizar_celula(txt, 80)))

    extras = [j for j in jails_reais if j and j not in JAILS_FAIL2BAN]
    if extras:
        linhas.append(("Jail", ", ".join(extras), "fail2ban-client", "🟡 NÃO monitorados", "-", "existem no fail2ban mas não estão em JAILS_FAIL2BAN"))

    for svc in SERVICOS_EXTRA:
        rc, out, err = _cmd(["/usr/bin/systemctl", "is-active", svc])
        estado = out.strip() or "desconhecido"
        linhas.append(("Serviço", svc, "systemctl", "🟢 ativo" if estado == "active" else f"🔴 {_sanitizar_celula(estado, 20)}", "-", ""))

    return pd.DataFrame(linhas, columns=["Tipo", "Fonte", "Origem", "Status", "Última atividade", "Detalhe"])


# ==========================================
# BARRA LATERAL (SIDEBAR)
# ==========================================
with st.sidebar:
    @st.fragment(run_every=10)
    def _painel_lateral_dinamico():
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disco = psutil.disk_usage('/').percent
        st.markdown("### 💻 Hardware do T430")
        st.progress(cpu / 100.0, text=f"Uso de CPU: {cpu}%")
        st.progress(ram / 100.0, text=f"Uso de RAM: {ram}%")
        st.progress(disco / 100.0, text=f"Uso de Disco: {disco}%")
        st.markdown("---")
        st.markdown("### 🔌 Sensores Operantes")
        servicos = {"Fail2Ban": "fail2ban", "SSH": "ssh", "Nginx": "nginx", "Suricata": "suricata"}
        for label, svc in servicos.items():
            ativo = verificar_servico(svc)
            st.markdown(f"{'🟢' if ativo else '🔴'} **{label}**")

    _painel_lateral_dinamico()
    st.markdown("---")
    st.markdown("### 🔔 Alertas")
    st.caption("Alertas locais via alerta_soc.sh (notify-send).")
    st.markdown("---")
    if st.button("🚪 Sair"):
        _log_auth("logout")
        st.session_state.clear()
        st.rerun()

# ==========================================
# PAINEL PRINCIPAL (ATUALIZAÇÃO SUAVE SEM PISCAR A TELA)
# ==========================================
st.title("🛡️ Centro de Operações de Segurança (SOC)")
st.markdown("---")


@st.fragment(run_every=10)
def _secao_monitoramento_ao_vivo():
    ocultar_ruido_padrao = st.session_state.get("ocultar_ruido_suricata", True)
    ocultar_proprio_padrao = st.session_state.get("ocultar_ip_proprio_suricata", True)

    df_suricata = ler_log_suricata(
        ocultar_ruido=ocultar_ruido_padrao,
        ocultar_ip_proprio=ocultar_proprio_padrao
    )
    df_nginx = ler_log_nginx()
    total_bloqueados, df_fail2ban = ler_dados_fail2ban()

    servicos = {"Fail2Ban": "fail2ban", "SSH": "ssh", "Nginx": "nginx", "Suricata": "suricata"}
    sensores_ativos = sum(int(verificar_servico(s)) for s in servicos.values())

    if alertas_recentes(df_suricata, 60) > 0:
        estado_perimetro = "Sob Ataque"
    elif total_bloqueados > 0:
        estado_perimetro = "Bloqueios Ativos"
    else:
        estado_perimetro = "Seguro"

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Ameaças Bloqueadas (Fail2Ban)", total_bloqueados)
    with col2:
        st.metric("Estado do Perímetro", estado_perimetro)
    with col3:
        st.metric("Sensores", f"{sensores_ativos}/{len(servicos)}")
    with col4:
        st.metric("Última Sincronização", datetime.datetime.now().strftime("%H:%M:%S"))

    st.markdown("---")

    aba_suricata, aba_fail2ban, aba_nginx, aba_saude = st.tabs([
        "Suricata (Tráfego de Rede)",
        "Fail2Ban (Prisão UFW)",
        "Nginx (Acessos Web WAF)",
        "Saúde do Sistema"
    ])

    with aba_suricata:
        c_f1, c_f2 = st.columns(2)
        with c_f1:
            st.checkbox(
                "Ocultar ruído de rede (STUN / Checksum UDPv6 / Retransmissões)",
                value=True,
                key="ocultar_ruido_suricata"
            )
        with c_f2:
            st.checkbox(
                "Ocultar tráfego de saída gerado por esta máquina (192.168.15.8)",
                value=True,
                key="ocultar_ip_proprio_suricata"
            )
        st.dataframe(df_suricata, width="stretch", hide_index=True)

    with aba_fail2ban:
        if not df_fail2ban.empty:
            st.error(f"⚠️ {total_bloqueados} IP(s) hostis neutralizados e bloqueados pelo Firewall.")
            st.dataframe(df_fail2ban, width="stretch", hide_index=True)
        else:
            st.success("Nenhuma atividade maliciosa bloqueada. A prisão está vazia.")

    with aba_nginx:
        st.caption("Registo das últimas tentativas de acesso ao seu servidor Web local.")
        st.dataframe(df_nginx, width="stretch", hide_index=True)

    with aba_saude:
        st.caption("Cada linha mostra se o painel CONSEGUE ler a fonte agora (com o usuário e as permissões do serviço).")
        df_fontes = fontes_de_log()
        n_ruins = int(df_fontes["Status"].str.startswith("🔴").sum())
        if n_ruins:
            st.error(f"⚠️ {n_ruins} fonte(s) com problema de leitura/serviço. Dados dessas fontes NÃO estão chegando ao painel.")
        else:
            st.success("Todas as fontes monitoradas estão sendo lidas.")
        st.dataframe(df_fontes, width="stretch", hide_index=True)


_secao_monitoramento_ao_vivo()

# ==========================================
# EDR SHADOW AI (ESTÁTICO E SEM PISCAR)
# ==========================================
st.markdown("---")
st.subheader("🛡️ Auditoria EDR: Shadow AI")

if st.button("Executar Varredura EDR Agora", key="btn_edr_scan"):
    with st.spinner("A varrer o sistema..."):
        try:
            ok_edr, motivo_edr = _arquivo_seguro_root(SCRIPT_EDR)
            if not ok_edr:
                raise RuntimeError(f"Script EDR rejeitado por segurança: {motivo_edr}")
            r = subprocess.run(
                ['/usr/bin/sudo', '-n', SCRIPT_EDR],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60, check=False
            )
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip() or f"Código de saída {r.returncode}")
            fontes_de_log.clear()
            st.success(f"Auditoria concluída com sucesso às {datetime.datetime.now().strftime('%H:%M:%S')}!")
        except Exception as e:
            st.error(f"Erro na execução do EDR: {_sanitizar_celula(e, 200)}")

try:
    if os.access(LOG_EDR, os.R_OK):
        relatorio_edr = "\n".join(_ultimas_linhas(LOG_EDR, 200)).strip()
    else:
        relatorio_edr = executar(['/usr/bin/sudo', '-n', '/usr/bin/cat', LOG_EDR]).strip()
except Exception:
    relatorio_edr = ""

if relatorio_edr:
    st.text_area("Último Relatório:", value=_sanitizar_celula(relatorio_edr, 8000), height=150, disabled=True)
