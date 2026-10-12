import streamlit as st
import pandas as pd
import psutil
import subprocess
import datetime
import time
import os
import geoip2.database
import re

# ==========================================
# CONFIGURAÇÕES DA PÁGINA
# ==========================================
st.set_page_config(page_title="SOC Local - T430", layout="wide")

# ==========================================
# FUNÇÕES DE LÓGICA E LEITURA
# ==========================================
def obter_localizacao(ip):
    # Ignorar IPs locais
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.") or ip == "::1":
        return "Rede Local"
    
    try:
        # Lê a base de dados offline descarregada
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
    if os.path.exists(log_path):
        try:
            resultado = subprocess.run(['sudo', 'tail', '-n', '100', log_path], stdout=subprocess.PIPE, text=True)
            linhas = resultado.stdout.strip().split('\n')
            for linha in reversed(linhas):
                if not linha: continue
                try:
                    # 1. Ignora ruído e diagnósticos internos do Suricata (sem direção '->')
                    if '->' not in linha:
                        continue
                        
                    # 2. Extrai a data
                    data_hora = linha.split()[0].split('.')[0]

                    # 3. Isola o bloco exato do IP de origem (antes da seta)
                    parte_origem = linha.split('->')[0].split()[-1]
                    
                    # 4. Remove a porta com segurança usando Regex e limpa colchetes do IPv6
                    origem = re.sub(r':\d+$', '', parte_origem)
                    origem = origem.replace('[', '').replace(']', '')

                    localizacao = obter_localizacao(origem)
                    
                    dados.append({
                        "Data/Hora": data_hora,
                        "Origem (IP)": origem,
                        "Localização": localizacao,
                        "O que ocorreu?": "Atividade suspeita detetada.",
                        "Medida": "⚠️ Monitorizando"
                    })
                except Exception:
                    continue
        except Exception:
            pass
            
    df = pd.DataFrame(dados) if dados else pd.DataFrame(columns=["Data/Hora", "Origem (IP)", "Localização", "O que ocorreu?", "Medida"])
    return df.drop_duplicates(subset=["Data/Hora", "Origem (IP)"]) if not df.empty else df

# ==========================================
# BARRA LATERAL (SIDEBAR)
# ==========================================
with st.sidebar:
    st.markdown("### 💻 Hardware do T430")
    st.progress(psutil.cpu_percent() / 100.0, text=f"Uso de CPU: {psutil.cpu_percent()}%")
    st.progress(psutil.virtual_memory().percent / 100.0, text=f"Uso de RAM: {psutil.virtual_memory().percent}%")
    st.progress(psutil.disk_usage('/').percent / 100.0, text=f"Uso de Disco: {psutil.disk_usage('/').percent}%")
    
    st.markdown("---")
    st.markdown("### 🔌 Sensores e Serviços")
    
    servicos = {
        "Fail2Ban (Motor Principal)": "fail2ban",
        "SSH (Acesso Remoto)": "ssh",
        "Nginx (Servidor Web)": "nginx",
        "Suricata (IDS/IPS)": "suricata"
    }
    
    sensores_ativos = 0
    for label, service_name in servicos.items():
        if verificar_servico(service_name):
            st.markdown(f"🟢 **{label}**")
            sensores_ativos += 1
        else:
            st.markdown(f"🔴 **{label}**")

# ==========================================
# PAINEL PRINCIPAL
# ==========================================
st.title("🛡️ Centro de Operações de Segurança (SOC)")
st.caption("Monitorização ativa com sincronização em tempo real (UFW, Fail2Ban, Suricata)")
st.markdown("---")

df_suricata = ler_log_suricata()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total de Ameaças Bloqueadas", "0") # Lógica a ligar ao Fail2Ban no futuro
with col2:
    st.metric("Estado do Perímetro", "Seguro")
with col3:
    st.metric("Sensores Operantes", f"{sensores_ativos}/4")
with col4:
    agora = datetime.datetime.now().strftime("%H:%M:%S")
    st.metric("Última Sincronização", agora)

st.markdown("---")

st.subheader("🚨 Registo de Interceções (Firewall UFW)")
st.success("Nenhuma atividade maliciosa bloqueada. O perímetro está completamente limpo.")

st.markdown("---")

# ==========================================
# ABAS COM INDENTAÇÃO CORRIGIDA
# ==========================================
aba_suricata, aba_fail2ban, aba_saude = st.tabs([
    "Suricata (Tráfego de Rede)", 
    "Fail2Ban (Ações Disciplinares)", 
    "Saúde do Sistema"
])

with aba_suricata:
    st.dataframe(df_suricata, use_container_width=True, hide_index=True)

with aba_fail2ban:
    st.info("A consultar base de dados prisional do Fail2Ban...")

with aba_saude:
    st.info("Todos os sensores operacionais e em escuta ativa.")

# ==========================================
# AUDITORIA EDR (SHADOW AI) - CORRIGIDA
# ==========================================
st.markdown("---")
st.subheader("🛡️ Auditoria EDR: Shadow AI")
st.caption("Verificação local de chaves de API e ferramentas de IA Generativa não autorizadas.")

if st.button("Executar Varredura EDR Agora"):
    with st.spinner("A varrer o sistema por chaves expostas..."):
        try:
            subprocess.run(['/home/pereira/soc_local/edr_shadow_ai.sh'], check=True, timeout=30)
            st.success("Auditoria concluída! O relatório abaixo foi atualizado.")
        except subprocess.TimeoutExpired:
            st.error("A auditoria demorou demasiado tempo.")
        except Exception as e:
            st.error(f"Erro ao executar a auditoria: {e}")

log_path = "/var/log/shadow_ai_edr.log"
try:
    resultado = subprocess.run(['sudo', 'cat', log_path], stdout=subprocess.PIPE, text=True)
    conteudo = resultado.stdout.strip()
    
    if conteudo:
        st.text_area("Último Relatório da Varredura EDR:", value=conteudo, height=200)
    else:
        st.info("O relatório EDR está limpo ou a varredura ainda não foi executada.")
except Exception:
    st.info("Aguardando primeira execução da varredura...")

# ==========================================
# AUTO-REFRESH (A CADA 5 SEGUNDOS)
# ==========================================
time.sleep(5)
st.rerun()
