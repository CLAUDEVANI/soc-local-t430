#!/bin/bash

LOG_FILE="/var/log/shadow_ai_edr.log"
DIRETORIOS="/opt/soc_local /home/gircp"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Iniciando varredura EDR para Shadow AI..." > "$LOG_FILE"

# Otimizado: usa find focado em extensões de código/config e pipes rápidos
find $DIRETORIOS -type f \( -name "*.py" -o -name "*.sh" -o -name "*.env" -o -name "*.json" -o -name "*.txt" -o -name "*.config" \) \
    -not -path "*/venv*" \
    -not -path "*/.git*" \
    -not -path "*/__pycache__*" \
    -not -path "*/.cache*" \
    2>/dev/null | xargs grep -lE "sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer [a-zA-Z0-9_\-\.]{20,}" 2>/dev/null | while read -r arquivo; do
        echo "[ACHADO] possível chave exposta em: $arquivo" >> "$LOG_FILE"
    done

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Varredura concluída. Verifique o painel do SOC." >> "$LOG_FILE"
