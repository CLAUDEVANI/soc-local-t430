#!/bin/bash

# ==========================================
# CREDENCIAIS DO TELEGRAM (Preencha aqui!)
# ==========================================
TOKEN="AAHozocF9vzyhLT9mq0aS3Fv-2QSSnigfk0"
CHAT_ID="8754928143"

ULTIMO=0

echo "Motor de Alertas SOC iniciado (Desktop + Telegram)..."

# Vigia o log do Fail2Ban aguardando a palavra "Ban"
tail -F /var/log/fail2ban.log | grep --line-buffered "Ban " | while read -r line ; do
    AGORA=$(date +%s)
    
    # Debounce (ignora caso não tenham passado 60 segundos desde a última notificação)
    (( AGORA - ULTIMO < 60 )) && continue
    ULTIMO=$AGORA
    
    # 1. Dispara o alerta nativo vermelho no desktop
    notify-send "🚨 SOC: Ataque Interceptado!" "Um invasor foi banido. Verifique o painel." -u critical
    
    # 2. Dispara o alerta móvel para o Telegram
    curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
        -d chat_id="$CHAT_ID" \
        -d text="🚨 *Alerta de Segurança (T430)* 🚨%0A%0A O motor Fail2Ban intercetou e baniu um invasor na infraestrutura. O perímetro foi assegurado.%0A%0A💻 _Verifique o painel do SOC para detalhes._" \
        -d parse_mode="Markdown" > /dev/null
done
