#!/bin/bash
DATA=$(date '+%Y-%m-%d %H:%M:%S')
LOG_FILE="/var/log/shadow_ai_edr.log"

# Limpa o log antigo para não acumular histórico de vazamentos passados
> "$LOG_FILE"

echo "[$DATA] Iniciando varredura EDR para Shadow AI..." | sudo tee -a "$LOG_FILE" > /dev/null

# Procura as chaves listando *apenas o nome dos arquivos* onde foram encontradas
echo "-> Verificando vazamento de chaves de API locais..."
sudo grep -rEl --include='*.txt' --include='*.env' --include='.env*' --include='*.py' --include='*.json' \
  -e 'sk-[A-Za-z0-9_-]{20,}' -e 'AKIA[0-9A-Z]{16}' -e 'ghp_[A-Za-z0-9]{36}' /home 2>/dev/null \
  | sed 's/^/[ACHADO] possível chave exposta em: /' | sudo tee -a "$LOG_FILE" > /dev/null

# Tranca o log para que apenas o root/adm consiga ler
sudo chmod 640 "$LOG_FILE"
sudo chown root:adm "$LOG_FILE"

echo "[$DATA] Varredura concluída. Verifique o painel do SOC." | sudo tee -a "$LOG_FILE" > /dev/null