# 🛡️ SOC Local - Fortaleza T430

Um Centro de Operações de Segurança (SOC) local e de grau corporativo construído em Python (Streamlit) para Ubuntu. 

## ⚙️ Funcionalidades
- **Monitorização UFW & Fail2Ban:** Visualização em tempo real de ataques intercetados.
- **IDS/IPS (Suricata):** Tradução de logs de tráfego e patrulha CASB contra Shadow AI (OpenAI, Anthropic, etc.).
- **Auditoria EDR:** Varredura ativa local por chaves de API expostas (Shadow AI).
- **Armadilha Honeypot:** Banimento automático de scanners que sondam portas vulneráveis (23, 3389, 445).
- **Proteção de Disco (ZFS):** Imunidade contra ransomware através de snapshots ZFS.

## 🔒 Segurança (Imutabilidade)
O código fonte e os ficheiros de configuração (`app.py`, `jail.local`, `suricata.yaml`) estão selados com o atributo de imutabilidade do Linux (`chattr +i`).
