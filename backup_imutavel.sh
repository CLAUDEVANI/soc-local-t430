#!/bin/bash
# Cofre Forense - Backups Imutáveis do SOC Local

SOC_DIR="/home/pereira/soc_local"
BACKUP_DIR="$SOC_DIR/backup"
DATA_ATUAL=$(date '+%Y-%m-%d_%H-%M')
ARQUIVO_FINAL="$BACKUP_DIR/soc_blindado_$DATA_ATUAL.tar.gz"

echo "A iniciar protocolo de selagem de provas..."

# Garante que a pasta de backup existe e destranca-a temporariamente para podermos guardar o ficheiro de hoje
mkdir -p "$BACKUP_DIR"
sudo chattr -i "$BACKUP_DIR" 2>/dev/null

# Comprime o código do SOC (ignorando a pasta venv pesada) e os logs vitais do sistema
sudo tar -czf "$ARQUIVO_FINAL" --exclude="$SOC_DIR/venv" "$SOC_DIR" /var/log/suricata/fast.log /var/log/nginx/access.log /var/log/shadow_ai_edr.log 2>/dev/null

# Aplica o cadeado de segurança máxima ao ficheiro gerado
sudo chattr +i "$ARQUIVO_FINAL"

echo "✅ Backup forense concluído e selado com imutabilidade em: $ARQUIVO_FINAL"

#!/bin/bash
DATA=$(date +%Y-%m-%d_%H-%M-%S)
PASTA_DESTINO="/home/pereira/soc_local/backups"
NOME_BACKUP="$PASTA_DESTINO/soc_backup_$DATA.tar.gz"

echo "1. A preparar o cofre de backups em $PASTA_DESTINO..."
mkdir -p $PASTA_DESTINO

echo "2. A compactar código-fonte e logs dos sensores..."
tar -czf $NOME_BACKUP \
    /home/pereira/soc_local/app.py \
    /home/pereira/soc_local/*.sh \
    /home/pereira/soc_local/README.md \
    /var/log/suricata/fast.log \
    /var/log/nginx/access.log \
    /var/log/fail2ban.log 2>/dev/null

echo "3. A aplicar blindagem Anti-Ransomware (chattr +i)..."
chattr +i $NOME_BACKUP

echo "✅ Backup concluído e selado com sucesso: $NOME_BACKUP"
