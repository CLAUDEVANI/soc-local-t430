import streamlit as st
import pandas as pd
import subprocess
import requests
import ipaddress
import html
import psutil
import os
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

# Configuração da página
st.set_page_config(page_title="SOC Local - T430", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st_autorefresh(interval=5000, limit=None, key="soc_counter")

# ==========================================
# FUNÇÕES DE SEGURANÇA E DADOS
# ==========================================
def desmascarar_ip(ip_str):
    ip_lower = ip_str.lower()
    if ip_lower.startswith('0064:ff9b:') or ip_lower.startswith('64:ff9b:'):
        partes = ip_lower.split(":")
        if len(partes) >= 8:
            hex_str = partes[-2].zfill(4) + partes[-1].zfill(4)
            try:
                ip_real = f"{int(hex_str[0:2], 16)}.{int(hex_str[2:4], 16)}.{int(hex_str[4:6], 16)}.{int(hex_str[6:8], 16)}"
                return ip_real, True
            except ValueError:
                return ip_str, False
    return ip_str, False

@st.cache_data(ttl=3600)
def obter_geolocalizacao(ip):
    try:
        ip_limpo, _ = desmascarar_ip(ip)
        ip_obj = ipaddress.ip_address(ip_limpo)
        ip_seguro = str(ip_obj)

        if ip_seguro.startswith(('192.168.', '10.', '172.', '127.', '::1', 'fe80:')):
            return "Rede Local", "N/A"
        if ip_seguro.startswith('2800:3f0:'):
            return "São Paulo, Brazil", "Google LLC"

        res = requests.get(f"http://ip-api.com/json/{ip_seguro}", timeout=2).json()
        if res.get('status') == 'success':
            return f"{html.escape(str(res.get('city', 'Desconhecido')))}, {html.escape(str(res.get('country', 'Desconhecido')))}", html.escape(str(res.get('isp', 'Desconhecido')))
        return "Desconhecido", "Desconhecido"
    except Exception:
        return "Desconhecido", "N/A"

def ler_banimentos():
    bans = []
    jails = ["suricata", "sshd", "nginx-botsearch"]
    for jail in jails:
        try:
            resultado = subprocess.run(['sudo', 'fail2ban-client', 'status', jail], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            for linha in resultado.stdout.splitlines():
                if "Banned IP list:" in linha:
                    ips_str = linha.split("Banned IP list:")[-1].strip()
                    if ips_str:
                        for ip in ips_str.split():
                            local, provedor = obter_geolocalizacao(ip)
                            if "Google" in provedor or provedor == "Injeção Bloqueada": continue
                            bans.append({"Data/Hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "IP": html.escape(ip), "Ação": "🔴 BLOQUEADO", "Origem": jail.upper(), "Local": local, "ISP": provedor})
        except Exception:
            pass
    return bans

def checar_servico(nome_servico):
    try:
        resultado = subprocess.run(['systemctl', 'is-active', nome_servico], stdout=subprocess.PIPE, text=True)
        return "🟢" if resultado.stdout.strip() == "active" else "🔴"
    except Exception:
        return "⚠️"

# ==========================================
# TRADUTOR HUMANO DE LOGS
# ==========================================
def ler_log_traduzido(caminho, tipo_log, linhas=100):
    try:
        resultado = subprocess.run(['sudo', 'tail', '-n', str(linhas), caminho], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        conteudo = resultado.stdout.strip()

        if not conteudo:
            return pd.DataFrame([{"Mensagem": "Nenhum evento recente."}])

        dados = []
        for linha in conteudo.splitlines():
            if not linha.strip(): continue

            if tipo_log == "suricata_alertas":
                if "ethertype unknown" in linha.lower() or "ipv6 unknown" in linha.lower(): 
                    continue 
                if "224.0.0." in linha or "ff02::" in linha.lower():
                    continue

                if "[**]" in linha:
                    partes = linha.split(" [**] ")
                    data_hora = linha.split(" ")[0].split(".")[0] if " " in linha else "Recente"
                    alerta_bruto = partes[1] if len(partes) > 1 else "Alerta"

                    if "invalid timestamp" in alerta_bruto.lower():
                        explicacao = "Tentativa de manipular pacote TCP."
                    else:
                        explicacao = "Atividade suspeita detetada."

                    ip_origem = "N/A (Pacote bruto)"
                    localizacao = "-"

                    if " -> " in linha:
                        try:
                            src_part = linha.split(" -> ")[0].strip().split()[-1]

                            if src_part.count(":") == 1:
                                ip_extraido = src_part.split(":")[0]
                            elif src_part.count(":") > 1:
                                ip_extraido = src_part.rsplit(":", 1)[0]
                            else:
                                ip_extraido = src_part

                            ip_real, foi_traduzido = desmascarar_ip(ip_extraido)

                            if foi_traduzido:
                                ip_origem = f"{ip_real} (Masc. NAT64)"
                            else:
                                ip_origem = ip_real

                            local, _ = obter_geolocalizacao(ip_real)
                            if local != "Dado Invalido" and local != "Erro/Invalido":
                                localizacao = local
                        except Exception:
                            pass

                    dados.append({
                        "Data/Hora": data_hora,
                        "Origem (IP)": ip_origem,
                        "Localização": localizacao,
                        "O que ocorreu?": explicacao,
                        "Medida": "⚠️ Monitorizando"
                    })

            elif tipo_log == "fail2ban":
                if len(linha) > 19:
                    data_hora = linha[:19]
                    if "Ban " in linha and "Unban" not in linha and "Restore" not in linha:
                        ip = linha.split("Ban ")[-1].strip()
                        ip_real, _ = desmascarar_ip(ip)
                        servico = linha.split("[")[2].split("]")[0] if "[" in linha else "Geral"
                        dados.append({"Data/Hora": data_hora, "Alvo/Serviço": ip_real, "Ação Tomada": f"🔴 BANIDO ({servico})", "Status": "Bloqueado no Firewall"})
                    elif "Found " in linha:
                        ip = linha.split("Found ")[-1].strip()
                        ip_real, _ = desmascarar_ip(ip)
                        dados.append({"Data/Hora": data_hora, "Alvo/Serviço": ip_real, "Ação Tomada": "🟡 Advertência", "Status": "Falha detetada. Somando erros"})
                    elif "Unban " in linha:
                        ip = linha.split("Unban ")[-1].strip()
                        ip_real, _ = desmascarar_ip(ip)
                        dados.append({"Data/Hora": data_hora, "Alvo/Serviço": ip_real, "Ação Tomada": "🟢 DESBLOQUEADO", "Status": "Castigo concluído"})
                    else:
                        dados.append({"Data/Hora": data_hora, "Alvo/Serviço": "Motor de Vigilância", "Ação Tomada": "ℹ️ Leitura de Rotina", "Status": "Inspecionando os sensores"})

            elif tipo_log == "suricata_sistema":
                status = "⚠️ Aviso/Erro" if any(x in linha for x in ["Error", "Warning", "ERR", "WARN", "Warn", "Fail"]) else "✅ Operação Normal"
                if " -- " in linha:
                    msg_real = linha.split(" -- ")[-1].strip()
                elif " - " in linha:
                    msg_real = linha.split(" - ")[-1].strip()
                else:
                    msg_real = linha.strip()

                data_bruta = linha.split(" - ")[0].split(" -- ")[0]
                if "]" in data_bruta:
                    data_hora = data_bruta.split("]")[-1].strip()
                else:
                    data_hora = data_bruta.strip()

                dados.append({"Data/Hora": data_hora[:25], "Estado": status, "Detalhe": msg_real})

        if not dados:
            return pd.DataFrame([{"Mensagem": "Apenas eventos de rotina normal."}])

        df = pd.DataFrame(dados).iloc[::-1]

        if tipo_log == "fail2ban":
            if 'Ação Tomada' in df.columns and 'Status' in df.columns:
                df = df.drop_duplicates(subset=['Ação Tomada', 'Status'])
        elif tipo_log == "suricata_alertas":
             if 'O que ocorreu?' in df.columns and 'Origem (IP)' in df.columns:
                df = df.drop_duplicates(subset=['O que ocorreu?', 'Origem (IP)', 'Medida'])
        elif tipo_log == "suricata_sistema":
            if 'Estado' in df.columns and 'Detalhe' in df.columns:
                df = df.drop_duplicates(subset=['Estado', 'Detalhe'])

        return df.head(25)

    except Exception as e:
        return pd.DataFrame([{"Erro": f"Erro de leitura: {e}"}])

# ==========================================
# INTERFACE LATERAL (SIDEBAR)
# ==========================================
with st.sidebar:
    st.header("💻 Hardware do T430")
    st.markdown("---")
    
    cpu_percent = psutil.cpu_percent()
    st.caption(f"**Uso de CPU:** {cpu_percent}%")
    st.progress(int(cpu_percent))
    
    ram_percent = psutil.virtual_memory().percent
    st.caption(f"**Uso de RAM:** {ram_percent}%")
    st.progress(int(ram_percent))
    
    disk_percent = psutil.disk_usage('/').percent
    st.caption(f"**Uso de Disco:** {disk_percent}%")
    st.progress(int(disk_percent))

    st.markdown("---")
    st.header("🔌 Sensores e Serviços")
    st.markdown(f"**{checar_servico('fail2ban')} Fail2Ban** (Motor Principal)")
    st.markdown(f"**{checar_servico('ssh')} SSH** (Acesso Remoto)")
    st.markdown(f"**{checar_servico('nginx')} Nginx** (Servidor Web)")
    st.markdown(f"**{checar_servico('suricata')} Suricata** (IDS/IPS)")

# ==========================================
# INTERFACE PRINCIPAL - DASHBOARD
# ==========================================
st.title("🛡️ Centro de Operações de Segurança (SOC)")
st.caption("Monitorização ativa com sincronização em tempo real (UFW, Fail2Ban, Suricata)")
st.markdown("---")

bans_df = pd.DataFrame(ler_banimentos())

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total de Ameaças Bloqueadas", len(bans_df) if not bans_df.empty else 0)
with col2:
    st.metric("Estado do Perímetro", "Seguro" if bans_df.empty else "Em Alerta")
with col3:
    st.metric("Sensores Operantes", "4/4")
with col4:
    st.metric("Última Sincronização", datetime.now().strftime("%H:%M:%S"))
st.markdown("---")
st.subheader("🚨 Registo de Interceções (Firewall UFW)")

if not bans_df.empty:
    st.dataframe(
        bans_df.style.applymap(lambda x: 'color: #ff4b4b; font-weight: bold' if x == '🔴 BLOQUEADO' else '', subset=['Ação']), 
        use_container_width=True,
        hide_index=True
    )
else:
    st.success("Nenhuma atividade maliciosa bloqueada. O perímetro está completamente limpo.")

# ==========================================
# LOGS EM TEMPO REAL
# ==========================================
st.markdown("---")
st.subheader("📡 Radar de Monitorização de Atividades (Em Direto)")
st.caption("Eventos traduzidos para leitura humana em tempo real.")

tab1, tab2, tab3 = st.tabs(["Suricata (Tráfego de Rede)", "Fail2Ban (Ações Disciplinares)", "Saúde do Sistema"])

with tab1:
    st.dataframe(ler_log_traduzido('/var/log/suricata/fast.log', 'suricata_alertas'), use_container_width=True, hide_index=True)
with tab2:
    st.dataframe(ler_log_traduzido('/var/log/fail2ban.log', 'fail2ban'), use_container_width=True, hide_index=True)
with tab3:
    st.dataframe(ler_log_traduzido('/var/log/suricata/suricata.log', 'suricata_sistema'), use_container_width=True, hide_index=True)

# ==========================================
# AUDITORIA EDR (SHADOW AI)
# ==========================================
st.markdown("---")
st.subheader("🛡️ Auditoria EDR: Shadow AI")
st.caption("Verificação local de chaves de API e ferramentas de IA Generativa não autorizadas.")

# 1. O botão apenas corre o script silenciosamente
if st.button("Executar Varredura EDR Agora"):
    with st.spinner("A varrer o sistema por chaves expostas..."):
        try:
            subprocess.run(['/home/pereira/soc_local/edr_shadow_ai.sh'], check=True, timeout=30)
            st.success("Auditoria concluída com sucesso! O relatório abaixo foi atualizado.")
        except subprocess.TimeoutExpired:
            st.error("A auditoria demorou demasiado tempo. Verifique se o script exige senha (sudo).")
        except Exception as e:
            st.error(f"Erro ao executar a auditoria: {e}")

# 2. A leitura do ficheiro fica DE FORA do botão, para estar sempre visível
log_path = "/var/log/shadow_ai_edr.log"
if os.path.exists(log_path):
    with open(log_path, "r") as f:
        resultado = f.read()
    st.text_area("Último Relatório da Varredura EDR:", value=resultado, height=200)
else:
    st.info("Nenhuma auditoria EDR registada ainda. Clique no botão acima para iniciar.")
