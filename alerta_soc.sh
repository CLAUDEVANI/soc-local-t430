#!/bin/bash
ULTIMO=0

# Vigia o log do Fail2Ban aguardando a palavra "Ban"
tail -F /var/log/fail2ban.log | grep --line-buffered "Ban " | while read -r line ; do
    AGORA=$(date +%s)
    
    # Debounce (ignora caso não tenham passado 60 segundos desde a última notificação)
    (( AGORA - ULTIMO < 60 )) && continue
    ULTIMO=$AGORA
    
    # Dispara um alerta nativo vermelho no desktop sem abrir spam de navegadores
    notify-send "🚨 SOC: Ataque Interceptado!" "Um invasor foi banido. Verifique o painel." -u critical
done