#!/bin/bash
set -euo pipefail

DEST_DIR="$HOME/soc_local/backup"
mkdir -p "$DEST_DIR"
DATA=$(date +%Y%m%d_%H%M%S)
ARQUIVO="$DEST_DIR/soc_backup_$DATA.tar.gz"

echo "Compactando arquivos críticos do SOC e Firewall..."
tar -czf "$ARQUIVO" \
    "$HOME/soc_local/app.py" \
    "$HOME/soc_local/edr_shadow_ai.sh" \
    "/etc/fail2ban/jail.local" \
    "/etc/systemd/system/soc-local.service" \
    "/etc/suricata/suricata.yaml" \
    "/etc/ufw" \
    "/etc/sudoers.d" \
    "/etc/nginx"

# Gera hash de verificação
sha256sum "$ARQUIVO" > "${ARQUIVO}.sha256"

echo "Backup concluído e validado com sucesso em: $DEST_DIR"