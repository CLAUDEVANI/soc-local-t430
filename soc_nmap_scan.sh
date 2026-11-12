#!/bin/bash
# Varredura de descoberta na LAN e portas locais do T430
# Executado via systemd timer com privilégios de root

TARGET_LAN="192.168.15.0/24"
JSON_OUT="/opt/soc_local/nmap_inventory.json"
TEMP_OUT="/tmp/nmap_inventory.tmp"

# 1. Descoberta rápida na LAN (-T4 -n para evitar lentidão e resolução DNS)
/usr/bin/nmap -T4 -n --max-rtt-timeout 200ms --host-timeout 10s -sn "$TARGET_LAN" -oX /tmp/nmap_lan.xml >/dev/null 2>&1

# 2. Varredura rápida de portas no próprio T430 para auditoria de firewall
/usr/bin/nmap -T4 -n --max-rtt-timeout 200ms --host-timeout 10s -p 22,80,443,8501,8080,9000 127.0.0.1 -oX /tmp/nmap_self.xml >/dev/null 2>&1

# 3. Processa os XMLs gerados e consolida em um JSON temporário
python3 - << 'EOF'
import json
import xml.etree.ElementTree as ET
import datetime

data = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "lan_hosts": [],
    "self_ports": []
}

# Parser da LAN
try:
    tree = ET.parse('/tmp/nmap_lan.xml')
    root = tree.getroot()
    for host in root.findall('host'):
        status = host.find('status')
        if status is not None and status.get('state') == 'up':
            ip = ""
            mac = ""
            vendor = "Desconhecido"
            for addr in host.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    ip = addr.get('addr')
                elif addr.get('addrtype') == 'mac':
                    mac = addr.get('addr')
                    vendor = addr.get('vendor', 'Desconhecido')
            if ip:
                data["lan_hosts"].append({"ip": ip, "mac": mac, "vendor": vendor})
except Exception:
    pass

# Parser de Portas Próprias (T430)
try:
    tree = ET.parse('/tmp/nmap_self.xml')
    root = tree.getroot()
    for host in root.findall('host'):
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                portid = port.get('portid')
                state_elem = port.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'
                service_elem = port.find('service')
                service = service_elem.get('name') if service_elem is not None else 'unknown'
                data["self_ports"].append({"port": portid, "state": state, "service": service})
except Exception:
    pass

with open('/tmp/nmap_inventory.json', 'w') as f:
    json.dump(data, f, indent=2)
EOF

# Move o JSON final com permissões corretas para a pasta do SOC
mv /tmp/nmap_inventory.json "$JSON_OUT"
chown root:root "$JSON_OUT"
chmod 644 "$JSON_OUT"
