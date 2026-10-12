#!/bin/bash
# Motor de Threat Intelligence - SOC Local

LOG_FILE="/var/log/soc_threat_intel.log"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Iniciando sincronização de Threat Intelligence..." > "$LOG_FILE"

# 1. Download silencioso da lista global da Emerging Threats
# 2. Filtra apenas IPs válidos com Regex
# 3. Extrai os 50 mais críticos para blindar o sistema sem sobrecarregar o UFW
IPS_MALICIOSOS=$(curl -s https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 50)

CONTADOR=0
for IP in $IPS_MALICIOSOS; do
    # Adiciona a regra de bloqueio ao UFW com uma etiqueta de identificação
    sudo ufw deny from $IP to any comment 'Threat-Intel-Global' > /dev/null
    CONTADOR=$((CONTADOR+1))
done

# Recarrega o firewall para aplicar as algemas
sudo ufw reload > /dev/null

echo "[$(date '+%Y-%m-%d %H:%M:%S')] $CONTADOR IPs maliciosos globais foram bloqueados proativamente." >> "$LOG_FILE"
echo "✅ Sincronização concluída! $CONTADOR ameaças bloqueadas."
