#!/bin/bash
DATA=$(date '+%Y-%m-%d %H:%M:%S')
LOG_FILE="/var/log/shadow_ai_edr.log"

echo "[$DATA] Iniciando varredura EDR para Shadow AI..." | sudo tee -a $LOG_FILE > /dev/null

# Procurar chaves de API locais
echo "-> Verificando vazamento de chaves de API locais..."
sudo grep -rEoh "(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|sk-ant-[a-zA-Z0-9_-]{20,})" /home/ --include=\*.{txt,env,py,json} 2>/dev/null | sudo tee -a $LOG_FILE

echo "[$DATA] Varredura concluída. Verifique o painel do SOC." | sudo tee -a $LOG_FILE > /dev/null
