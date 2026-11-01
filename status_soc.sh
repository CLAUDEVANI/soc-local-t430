#!/bin/bash
echo "=== 1. FIREWALL (UFW) ===" && sudo ufw status verbose
echo -e "\n=== 2. IDS (Suricata) ===" && sudo systemctl is-active suricata
echo -e "\n=== 3. RESPOSTA (Fail2Ban) ===" && sudo systemctl is-active fail2ban && sudo fail2ban-client status suricata
echo -e "\n=== 4. PAINEL SOC (Streamlit) ===" && sudo systemctl is-active soc-local.service
echo -e "\n=== 5. ALERTA VISUAL (Daemon) ===" && pgrep -f alerta_soc.sh > /dev/null && echo "Rodando (Ativo)" || echo "Parado"
