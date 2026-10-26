import streamlit as st
import pandas as pd
import psutil
import subprocess
import datetime
import time
import os
import geoip2.database
import re
import requests

# ==========================================
# CONFIGURAÇÕES DA PÁGINA
# ==========================================
st.set_page_config(page_title="SOC Local - T430", layout="wide")

# ==========================================
# CREDENCIAIS DO TELEGRAM BOT
# ==========================================
TELEGRAM_TOKEN = "8530780213:AAHozocF9vzyhLT9mq0aS3Fv-2QSSnigfk0"
TELEGRAM_CHAT_ID = "588759475"

# ==========================================
# FUNÇÕES DE LÓGICA E LEITURA
# ==========================================
def enviar_alerta_telegram(mensagem):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": mensagem,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, data=payload, timeout=5)
    except Exception:
        pass

def obter_localizacao(ip):
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.") or ip == "::1":
        return "Rede Local"
    try:
        with geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
            resposta = reader.city(ip)
            cidade = resposta.city.name or "Desconhecido"
            pais = resposta.country.name or "Desconhecido"
            return f"{cidade}, {pais}"
    except Exception:
        return "Desconhecido"

def verificar_servico(nome_servico):
    try:
        resultado = subprocess.run(['systemctl', 'is-active', nome_servico], stdout=subprocess.PIPE, text=True)
        return resultado.stdout.strip() == 'active'
    except Exception:
        return False

@st.cache_data(ttl=5)
def ler_log_suricata():
    dados = []
    log_path = "/var/log/suricata/fast.log"
    
    ips_ignorados = ["192.168.15.3", "192.168.15.7"] 
    # Filtro da Fastly/GitHub adicionado
    prefixos_ignorados = ["2001:4860:", "2804:07f0:", "151.101."] 

    if os.path.exists(log_path):
        try:
            resultado = subprocess.run(['sudo', 'tail', '-n', '100', log_path], stdout=subprocess.PIPE, text=True)
            for linha in reversed(resultado.stdout.strip().split('\n')):
                if not linha or '->' not in linha: continue
                try:
                    data_hora = linha.split()[0].split('.')[0]
                    parte_origem = linha.split('->')[0].split()[-1]
                    origem = re.sub(r':\d+$', '', parte_origem).replace('[', '').replace(']', '')
                    
                    if origem in ips_ignorados or any(origem.startswith(prefixo) for prefixo in prefixos_ignorados):
                        continue
                        
                    dados.append({
                        "Data/Hora": data_hora,
                        "Origem (IP)": origem,
                        "Localização": obter_localizacao(origem),
                        "O que ocorreu?": "Atividade suspeita detetada.",
                        "Medida": "⚠️ Monitorizando"
                    })
                except Exception:
                    continue
        except Exception:
            pass
    df = pd.DataFrame(dados) if dados else pd.DataFrame(columns=["Data/Hora", "Origem (IP)", "Localização", "O que ocorreu?", "Medida"])
    return df.drop_duplicates(subset=["Data/Hora", "Origem (IP)"]) if not df.empty else df

@st.cache_data(ttl=5)
def ler_dados_fail2ban():
    try:
        resultado = subprocess.run(['sudo', 'fail2ban-client', 'status', 'suricata'], stdout=subprocess.PIPE, text=True)
        texto = resultado.stdout
        
        atualmente_banidos = re.search(r'Currently banned:\s+(\d+)', texto)
        banned_ips = re.search(r'Banned IP list:\s+(.*)', texto)
        
        total = atualmente_banidos.group(1) if atualmente_banidos else "0"
        ips = banned_ips.group(1).split() if banned_ips and banned_ips.group(1).strip() else []
        
        dados_f2b = []
        novos_bloqueios = []
        
        # Motor de Memória: Verifica se o IP já foi notificado antes
        ficheiro_memoria = "/home/pereira/soc_local/ips_alertados.txt"
        ips_ja_alertados = set()
        if os.path.exists(ficheiro_memoria):
            with open(ficheiro_memoria, "r") as f:
                ips_ja_alertados = set(f.read().splitlines())

        for ip in ips:
            loc = obter_localizacao(ip)
            dados_f2b.append({
                "Origem (IP)": ip,
                "Localização": loc,
                "Estado": "🔒 Bloqueado",
                "Prisão": "suricata"
            })
            
            # Regra de Gatilho: Prepara o alerta se for um alvo inédito
            if ip not in ips_ja_alertados:
                novos_bloqueios.append((ip, loc))
                ips_ja_alertados.add(ip)
        
        # Grava os novos IPs na memória e dispara os alertas no Telegram
        if novos_bloqueios:
            try:
                with open(ficheiro_memoria, "w") as f:
                    f.write("\n".join(ips_ja_alertados))
                
                for nip, nloc in novos_bloqueios:
                    mensagem = f"🛡️ *SOC T430: NOVO BLOQUEIO*\n\n*IP Hostil:* `{nip}`\n*Local:* {nloc}\n*Ação:* Neutralizado pelo Firewall (Fail2Ban)."
                    enviar_alerta_telegram(mensagem)
            except Exception:
                pass

        return total, pd.DataFrame(dados_f2b) if dados_f2b else pd.DataFrame(columns=["Origem (IP)", "Localização", "Estado", "Prisão"])
    except Exception:
        return "0", pd.DataFrame(columns=["Origem (IP)", "Localização", "Estado", "Prisão"])

@st.cache_data(ttl=5)
def ler_log_nginx():
    dados = []
    log_path = "/var/log/nginx/access.log"
    if os.path.exists(log_path):
        try:
            resultado = subprocess.run(['sudo', 'tail', '-n', '50', log_path], stdout=subprocess.PIPE, text=True)
            for linha in reversed(resultado.stdout.strip().split('\n')):
                if not linha: continue
                try:
                    partes = linha.split()
                    ip = partes[0]
                    data_hora = partes[3].replace('[', '')
                    metodo = partes[5].replace('"', '')
                    rota = partes[6]
                    status = partes[8]
                    
                    dados.append({
                        "Data/Hora": data_hora,
                        "Origem (IP)": ip,
                        "Método": metodo,
                        "Rota Acedida": rota,
                        "Status": status
                    })
                except Exception:
                    continue
        except Exception:
            pass
    return pd.DataFrame(dados) if dados else pd.DataFrame(columns=["Data/Hora", "Origem (IP)", "Método", "Rota Acedida", "Status"])

# ==========================================
# BARRA LATERAL (SIDEBAR)
# ==========================================
with st.sidebar:
    st.markdown("### 💻 Hardware do T430")
    st.progress(psutil.cpu_percent() / 100.0, text=f"Uso de CPU: {psutil.cpu_percent()}%")
    st.progress(psutil.virtual_memory().percent / 100.0, text=f"Uso de RAM: {psutil.virtual_memory().percent}%")
    
    st.markdown("---")
    st.markdown("### 🔌 Sensores Operantes")
    servicos = {"Fail2Ban": "fail2ban", "SSH": "ssh", "Nginx": "nginx", "Suricata": "suricata"}
    sensores_ativos = sum(1 for label, svc in servicos.items() if verificar_servico(svc) and st.markdown(f"🟢 **{label}**") or not verificar_servico(svc) and st.markdown(f"🔴 **{label}**") is None)
    
    st.markdown("---")
    st.markdown("### 🔔 Alertas (Webhook)")
    webhook_ativo = st.toggle("Ativar Notificações (Telegram/Discord)", value=True)
    if webhook_ativo:
        st.success("Telegram conectado e ativo.")
    else:
        st.warning("Notificações em pausa.")

# ==========================================
# PAINEL PRINCIPAL
# ==========================================
st.title("🛡️ Centro de Operações de Segurança (SOC)")
st.markdown("---")

df_suricata = ler_log_suricata()
df_nginx = ler_log_nginx()
total_bloqueados, df_fail2ban = ler_dados_fail2ban()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Ameaças Bloqueadas (Fail2Ban)", total_bloqueados)
with col2:
    estado_perimetro = "Sob Ataque" if int(total_bloqueados) > 0 else "Seguro"
    st.metric("Estado do Perímetro", estado_perimetro)
with col3:
    st.metric("Sensores", f"{sensores_ativos}/4")
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
            subprocess.run(['/home/pereira/soc_local/edr_shadow_ai.sh'], check=True, timeout=30)
            st.success("Auditoria concluída!")
        except Exception as e:
            st.error(f"Erro: {e}")

try:
    resultado = subprocess.run(['sudo', 'cat', '/var/log/shadow_ai_edr.log'], stdout=subprocess.PIPE, text=True)
    if resultado.stdout.strip():
        st.text_area("Último Relatório:", value=resultado.stdout.strip(), height=150)
except Exception:
    pass

time.sleep(5)
st.rerun()
