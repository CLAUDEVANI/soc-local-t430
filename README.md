# 🛡️ SOC Local - T430 Fortress

Um Centro de Operações de Segurança (SOC) local e autônomo, construído para Ubuntu/Debian. Este projeto transforma um endpoint comum numa fortaleza blindada, integrando monitoramento de rede, EDR para Shadow AI e defesas ativas contra invasores, tudo centralizado num dashboard em tempo real feito com Streamlit.

## ✨ Arquitetura e Funcionalidades

*   **Dashboard Interativo (Streamlit):** Painel web leve que centraliza logs do sistema, traduz alertas para leitura humana e mostra o uso de hardware.
*   **Defesa Ativa (Fail2Ban + UFW):**
    *   Bloqueio automático de IPs maliciosos.
    *   **Honeypot Ativo:** Bane instantaneamente scanners de rede que toquem em portas iscas (23, 3389, 445).
    *   Firewall em modo "Stealth" (Pings e mDNS bloqueados, apenas SSH restrito permitido).
*   **Inspeção de Rede (Suricata IDS):** Monitoramento de tráfego TLS/DNS para identificar violações de políticas e acessos a ferramentas de IA Generativa não aprovadas.
*   **Auditoria EDR (Shadow AI):** Script de varredura profunda para detectar chaves de API vazadas (`sk-ant-`, `sk-proj-`) nos arquivos do usuário.
*   **Resiliência (ZFS & Logrotate):**
    *   Autolimpeza semanal de logs.
    *   Snapshots instantâneos do sistema de arquivos ZFS para proteção contra Ransomware.

## 🚀 Tecnologias Utilizadas

*   **Python 3:** Streamlit, Pandas, Psutil, Requests.
*   **Linux Security:** UFW, Fail2Ban, Suricata.
*   **Filesystem:** ZFS (Snapshots imutáveis).

## 🛠️ Instalação e Uso

1.  **Requisitos:** Ubuntu/Debian com `ufw`, `fail2ban` e `suricata` instalados.
2.  **Clonar o Repositório:**
    ```bash
    git clone https://github.com/SEU-USUARIO/soc-local-t430.git
    cd soc-local-t430
    ```
3.  **Configurar o Ambiente:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install streamlit pandas psutil requests streamlit-autorefresh
    ```
4.  **Iniciar o Dashboard:**
    ```bash
    streamlit run app.py
    ```

## 🔐 Nota de Segurança
Os arquivos críticos de configuração deste projeto foram desenhados para operar sob bloqueio de imutabilidade (`chattr +i`) no kernel do Linux, garantindo que nem mesmo usuários com privilégios de root possam desativar as defesas acidentalmente ou por ação de malware.

---
*Construído com foco em segurança máxima e resiliência de endpoint.*
