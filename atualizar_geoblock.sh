#!/bin/bash
echo "1. A preparar a tabela de memória do IPSet (Geo-Blocking)..."
ipset flush geoblock || ipset create geoblock hash:net

echo "2. A descarregar e injetar IPs da Rússia (aguarde)..."
curl -s --connect-timeout 10 --max-time 30 https://www.ipdeny.com/ipblocks/data/countries/ru.zone | awk '{print "add geoblock " $1}' | ipset restore

echo "3. A descarregar e injetar IPs da China (aguarde)..."
curl -s --connect-timeout 10 --max-time 30 https://www.ipdeny.com/ipblocks/data/countries/cn.zone | awk '{print "add geoblock " $1}' | ipset restore

echo "4. A preparar a tabela de Threat Intelligence Global..."
ipset flush threat_intel || ipset create threat_intel hash:net

echo "5. A descarregar e injetar cibercriminosos conhecidos (FireHOL)..."
curl -s --connect-timeout 10 --max-time 30 https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset | grep -v "^#" | awk '{print "add threat_intel " $1}' | ipset restore

echo "6. Atualização de escudos concluída com sucesso!"
