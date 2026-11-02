import streamlit as st
import pandas as pd
import psutil
import subprocess
import datetime
import os
import hmac
import ipaddress
import re
import geoip2.database
from streamlit_autorefresh import st_autorefresh
import time
import pyotp

# ==========================================
# CONFIGURAÇÕES DA PÁGINA
# ==========================================
st.set_page_config(page_title="SOC Local - T430", layout="wide")

# ==========================================
# AUTENTICAÇÃO (Senha + 2FA TOTP) - fail-closed
# Variáveis obrigatórias (EnvironmentFile 600 root:root):
#   SOC_PASSWORD, SOC_TOTP_SECRET
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
    return {"falhas": 0, "bloqueado_ate": 0.0, "ultimo_passo": 0}


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
    print(f"[SOC-AUTH] {datetime.datetime.now().isoformat(timespec='seconds')} ip={_ip_cliente()} {msg}", flush=True)


def _registrar_falha(motivo):
    e = _estado_login()
    e["falhas"] += 1
    _log_auth(f"falha de login ({motivo}); tentativas={e['falhas']}")
    if e["falhas"] >= MAX_FALHAS:
        e["bloqueado_ate"] = time.time() + BLOQUEIO_SEGUNDOS
        e["falhas"] = 0
        _log_auth(f"login bloqueado por {BLOQUEIO_SEGUNDOS}s")


def _verificar_totp(codigo):
    if not (codigo.isdigit() and len(codigo) == 6):
        return False
    totp = pyotp.TOTP(TOTP_SECRET)
    passo_atual = int(time.time() // totp.interval)
    e = _estado_login()
    for desloc in (-1, 0, 1):
        if hmac.compare_digest(totp.at(time.time(), desloc), codigo):
            passo = passo_atual + desloc
            if passo <= e["ultimo_passo"]:
                return False
            e["ultimo_passo"] = passo
            return True
    return False

if st.session_state.get("autenticado") and \
        time.time() - st.session_state.get("auth_ts", 0) > SESSAO_MAX_SEGUNDOS:
    st.session_state.clear()
    st.warning("Sessão expirada. Autentique-se novamente.")

if not st.session_state.get("autenticado"):
    if time.time() < _estado_login()["bloqueado_ate"]:
        st.error("Muitas tentativas. Aguarde alguns minutos.")
        st.stop()

    if not st.session_state.get("senha_ok"):
        st.title("🔒 SOC Local - Acesso Restrito (Passo 1/2)")
        senha = st.text_input("Senha", type="password")
        if senha:
            if hmac.compare_digest(senha.encode(), SENHA_PAINEL.encode()):
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
            st.session_state["autenticado"] = True
            st.session_state["auth_ts"] = time.time()
            st.session_state.pop("senha_ok", None)
            _log_auth("login bem-sucedido")
            st.rerun()
        else:
            _registrar_falha("totp")
            st.error("Credenciais inválidas.")
    st.stop()

st_autorefresh(interval=5000, key="soc_refresh")

# ==========================================
# CONSTANTES
# ==========================================
GEOIP_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
JAILS_FAIL2BAN = ["endlessh", "nginx-botsearch", "recidive", "soc-auth", "sshd", "suricata", "ufw-honeypot"]
LOG_SURICATA = "/var/log/suricata/fast.log"
LOG_NGINX = "/var/log/nginx/access.log"
SCRIPT_EDR = "/opt/soc_local/edr_shadow_ai.sh"
LOG_EDR = "/var/log/shadow_ai_edr.log"

COLUNAS_SURICATA = ["Data/Hora", "Origem (IP)", "Localização", "O que ocorreu?", "Medida"]
COLUNAS_F2B = ["Origem (IP)", "Localização", "Estado", "Prisão"]
COLUNAS_NGINX = ["Data/Hora", "Origem (IP)", "Método", "Rota Acedida", "Status"]
PADRAO_NGINX = re.compile(r'^(\S+) \S+ \S+ \[(.*?)\] "(?:(\S+) )?(.*?)(?: HTTP/\d\.\d)?" (\d+)')

def executar(comando, timeout=5):
    try:
        resultado = subprocess.run(
            comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=timeout
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
        return f"{cidade}, {pais}"
    except Exception:
        return "Desconhecido"


def verificar_servico(nome_servico):
    return executar(['systemctl', 'is-active', nome_servico]).strip() == 'active'


def alertas_recentes(df, minutos=60):
    if df.empty:
        return 0
    agora = datetime.datetime.now()
    total = 0
    for marca in df["Data/Hora"]:
        try:
            momento = datetime.datetime.strptime(marca, "%m/%d/%Y-%H:%M:%S")
            if (agora - momento).total_seconds() <= minutos * 60:
                total += 1
        except ValueError:
            continue
    return total


@st.cache_data(ttl=5)
def ler_log_suricata():
    dados = []
    ips_ignorados = ["192.168.15.3"]
    try:
        with open(LOG_SURICATA, "r") as f:
            linhas = f.readlines()
        for linha in reversed(linhas[-100:]):
            if not linha or '->' not in linha:
                continue
            try:
                data_hora = linha.split()[0].split('.')[0]
                parte_origem = linha.split('->')[0].split()[-1]
                origem = re.sub(r':\d+$', '', parte_origem).replace('[', '').replace(']', '')

                if origem in ips_ignorados:
                    continue

                m = re.search(r'\[\*\*\]\s*\[[\d:]+\]\s*(.*?)\s*\[\*\*\]', linha)
                descricao = m.group(1) if m else "Atividade suspeita detetada."

                dados.append({
                    "Data/Hora": data_hora,
                    "Origem (IP)": origem,
                    "Localização": obter_localizacao(origem),
                    "O que ocorreu?": descricao,
                    "Medida": "⚠️ Monitorizando"
                })
            except Exception:
                continue
    except Exception:
        pass

    if not dados:
        return pd.DataFrame(columns=COLUNAS_SURICATA)
    df = pd.DataFrame(dados)
    return df.drop_duplicates(subset=["Data/Hora", "Origem (IP)", "O que ocorreu?"])


@st.cache_data(ttl=5)
def ler_dados_fail2ban():
    dados_f2b = []
    for jail in JAILS_FAIL2BAN:
        texto = executar(['fail2ban-client', 'status', jail])
        m = re.search(r'Banned IP list:\s*(.*)', texto)
        ips = m.group(1).split() if m and m.group(1).strip() else []
        for ip in ips:
            dados_f2b.append({
                "Origem (IP)": ip,
                "Localização": obter_localizacao(ip),
                "Estado": "🔒 Bloqueado",
                "Prisão": jail
            })
    if not dados_f2b:
        return 0, pd.DataFrame(columns=COLUNAS_F2B)
    df = pd.DataFrame(dados_f2b)
    return len(dados_f2b), df


@st.cache_data(ttl=5)
def ler_log_nginx():
    dados = []
    saida = executar(['tail', '-n', '50', LOG_NGINX])
    for linha in reversed(saida.strip().split('\n')):
        if not linha:
            continue
        m = PADRAO_NGINX.match(linha)
        if not m:
            continue
        ip, data_hora, metodo, rota, status = m.groups()
        dados.append({
            "Data/Hora": data_hora,
            "Origem (IP)": ip,
            "Método": metodo or "GET",
            "Rota Acedida": rota or "/",
            "Status": status or "200"
        })
    return pd.DataFrame(dados) if dados else pd.DataFrame(columns=COLUNAS_NGINX)

# ==========================================
# BARRA LATERAL (SIDEBAR)
# ==========================================
with st.sidebar:
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
    sensores_ativos = 0
    for label, svc in servicos.items():
        ativo = verificar_servico(svc)
        sensores_ativos += int(ativo)
        st.markdown(f"{'🟢' if ativo else '🔴'} **{label}**")

    st.markdown("---")
    st.markdown("### 🔔 Alertas")
    st.caption("Alertas locais via alerta_soc.sh (notify-send).")

    st.markdown("---")
    if st.button("🚪 Sair"):
        _log_auth("logout")
        st.session_state.clear()
        st.rerun()

# ==========================================
# PAINEL PRINCIPAL
# ==========================================
st.title("🛡️ Centro de Operações de Segurança (SOC)")
st.markdown("---")

df_suricata = ler_log_suricata()
df_nginx = ler_log_nginx()
total_bloqueados, df_fail2ban = ler_dados_fail2ban()

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

# ==========================================
# ABAS DE ANÁLISE FORENSE
# ==========================================
aba_suricata, aba_fail2ban, aba_nginx, aba_saude = st.tabs([
    "Suricata (Tráfego de Rede)",
    "Fail2Ban (Prisão UFW)",
    "Nginx (Acessos Web WAF)",
    "Saúde do Sistema"
])

with aba_suricata:
    st.dataframe(df_suricata, use_container_width=True, hide_index=True)

with aba_fail2ban:
    if not df_fail2ban.empty:
        st.error(f"⚠️ {total_bloqueados} IP(s) hostis neutralizados e bloqueados pelo Firewall.")
        st.dataframe(df_fail2ban, use_container_width=True, hide_index=True)
    else:
        st.success("Nenhuma atividade maliciosa bloqueada. A prisão está vazia.")

with aba_nginx:
    st.caption("Registo das últimas tentativas de acesso ao seu servidor Web local.")
    st.dataframe(df_nginx, use_container_width=True, hide_index=True)

with aba_saude:
    st.info("Sensores operacionais. Motor de Threat Intelligence e Backups Imutáveis automatizados.")

# ==========================================
# EDR SHADOW AI
# ==========================================
st.markdown("---")
st.subheader("🛡️ Auditoria EDR: Shadow AI")
if st.button("Executar Varredura EDR Agora"):
    with st.spinner("A varrer o sistema..."):
        try:
            subprocess.run(['sudo', SCRIPT_EDR], check=True, timeout=30)
            st.success("Auditoria concluída!")
        except Exception as e:
            st.error(f"Erro: {e}")

relatorio_edr = executar(['sudo', 'cat', LOG_EDR]).strip()
if relatorio_edr:
    st.text_area("Último Relatório:", value=relatorio_edr, height=150)
