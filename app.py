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

# ==========================================
# CONFIGURAÇÕES DA PÁGINA
# ==========================================
st.set_page_config(page_title="SOC Local - T430", layout="wide")

# ==========================================
# AUTENTICAÇÃO (opcional)
# Defina SOC_PASSWORD no ambiente (ex.: EnvironmentFile do systemd)
# para exigir senha no painel. Sem a variável, o painel abre direto.
# ==========================================
SENHA_PAINEL = os.environ.get("SOC_PASSWORD", "")
if SENHA_PAINEL and not st.session_state.get("autenticado"):
    st.title("🔒 SOC Local - Acesso restrito")
    senha_digitada = st.text_input("Senha", type="password")
    if senha_digitada:
        if hmac.compare_digest(senha_digitada, SENHA_PAINEL):
            st.session_state["autenticado"] = True
            st.rerun()
        else:
            st.error("Senha incorreta.")
    st.stop()

# Atualização automática (substitui time.sleep + st.rerun)
st_autorefresh(interval=5000, key="soc_refresh")

# ==========================================
# CONSTANTES
# ==========================================
GEOIP_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
JAILS_FAIL2BAN = ["suricata", "sshd", "nginx-botsearch"]
LOG_SURICATA = "/var/log/suricata/fast.log"
LOG_NGINX = "/var/log/nginx/access.log"
SCRIPT_EDR = "/home/pereira/soc_local/edr_shadow_ai.sh"
LOG_EDR = "/var/log/shadow_ai_edr.log"

COLUNAS_SURICATA = ["Data/Hora", "Origem (IP)", "Localização", "O que ocorreu?", "Medida"]
COLUNAS_F2B = ["Origem (IP)", "Localização", "Estado", "Prisão"]
COLUNAS_NGINX = ["Data/Hora", "Origem (IP)", "Método", "Rota Acedida", "Status"]

# ==========================================
# FUNÇÕES DE LÓGICA E LEITURA
# ==========================================
def executar(comando, timeout=5):
    """Executa um comando com timeout e devolve o stdout ('' em caso de falha)."""
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
    """Conta alertas do Suricata dentro da janela de tempo informada."""
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

    ips_ignorados = ["192.168.15.3", "192.168.15.7"]
    # Filtro da Fastly/GitHub adicionado
    prefixos_ignorados = ["2001:4860:", "2804:07f0:", "151.101."]

    if os.path.exists(LOG_SURICATA):
        saida = executar(['sudo', 'tail', '-n', '100', LOG_SURICATA])
        for linha in reversed(saida.strip().split('\n')):
            if not linha or '->' not in linha:
                continue
            try:
                data_hora = linha.split()[0].split('.')[0]
                parte_origem = linha.split('->')[0].split()[-1]
                origem = re.sub(r':\d+$', '', parte_origem).replace('[', '').replace(']', '')

                if origem in ips_ignorados or any(origem.startswith(p) for p in prefixos_ignorados):
                    continue

                # Assinatura real da regra (ex.: "ET SCAN Potential SSH Scan")
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
    if not dados:
        return pd.DataFrame(columns=COLUNAS_SURICATA)
    df = pd.DataFrame(dados)
    return df.drop_duplicates(subset=["Data/Hora", "Origem (IP)", "O que ocorreu?"])


@st.cache_data(ttl=5)
def ler_dados_fail2ban():
    dados_f2b = []
    for jail in JAILS_FAIL2BAN:
        texto = executar(['sudo', 'fail2ban-client', 'status', jail])
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
    return int(df["Origem (IP)"].nunique()), df


PADRAO_NGINX = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3})')


@st.cache_data(ttl=5)
def ler_log_nginx():
    dados = []
    if os.path.exists(LOG_NGINX):
        saida = executar(['sudo', 'tail', '-n', '50', LOG_NGINX])
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
                "Método": metodo,
                "Rota Acedida": rota,
                "Status": status
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
    st.info("Sensores operacionais. Motor de Threat Intelligence e Backups Imutáveis automatizados.")

# ==========================================
# EDR SHADOW AI
# ==========================================
st.markdown("---")
st.subheader("🛡️ Auditoria EDR: Shadow AI")
if st.button("Executar Varredura EDR Agora"):
    with st.spinner("A varrer o sistema..."):
        try:
            subprocess.run([SCRIPT_EDR], check=True, timeout=30)
            st.success("Auditoria concluída!")
        except Exception as e:
            st.error(f"Erro: {e}")

relatorio_edr = executar(['sudo', 'cat', LOG_EDR]).strip()
if relatorio_edr:
    st.text_area("Último Relatório:", value=relatorio_edr, height=150)
