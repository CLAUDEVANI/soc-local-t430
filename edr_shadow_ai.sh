#!/bin/bash

LOG_FILE="/var/log/shadow_ai_edr.log"
# Define as pastas base a procurar
DIRETORIOS="/home/pereira/soc_local /home/gircp"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Iniciando varredura EDR para Shadow AI..." > "$LOG_FILE"

# O comando grep agora ignora ativamente as pastas ruidosas de sistema, pacotes e cache
arquivos_suspeitos=$(grep -rlE "sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer [a-zA-Z0-9_\-\.]{20,}" \
    --exclude-dir={venv,venv_soc,.vscode,.git,__pycache__,snap,.mozilla,.cache} \
    $DIRETORIOS 2>/dev/null)

if [ -n "$arquivos_suspeitos" ]; then
    for arquivo in $arquivos_suspeitos; do
        echo "[ACHADO] possível chave exposta em: $arquivo" >> "$LOG_FILE"
    done
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Varredura concluída. Verifique o painel do SOC." >> "$LOG_FILE"
