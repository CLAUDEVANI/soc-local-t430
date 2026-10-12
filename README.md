# 🛡️ SOC Local (Centro de Operações de Segurança) - ThinkPad T430

Um Centro de Operações de Segurança (SOC) de nível empresarial (*Enterprise-Grade*) desenvolvido especificamente para ambiente local Linux (Ubuntu) no ThinkPad T430. O sistema integra monitorização em tempo real, deteção de intrusão, inteligência de ameaças proativa, auditoria EDR, backups forenses imutáveis e alertas móveis via Telegram.

---

## 🏗️ Arquitetura e Componentes do Sistema

O ecossistema divide-se em motores de infraestrutura em segundo plano e uma interface gráfica interativa desenvolvida em **Streamlit**.

### 1. Painel Visual de Controlo (`app.py`)
* **Framework:** Streamlit (Layout em widescreen).
* **Métricas em Tempo Real:** Monitorização de recursos de hardware (CPU, RAM, Disco) via `psutil`, estado dos sensores operantes e contagem de ameaças ativas.
* **Geolocalização Offline:** Integração com a base de dados MaxMind GeoLite2 City (`.mmdb`) para mapear a origem geográfica dos IPs maliciosos.
* **Abas de Análise Forense:**
  - **Suricata:** Registo de pacotes de rede suspeitos com filtragem avançada de ruído e parsing de IPv4/IPv6.
  - **Fail2Ban (Prisão UFW):** Monitorização dinâmica dos IPs atualmente bloqueados pelo firewall.
  - **Nginx (WAF):** Registo de acessos web, métodos HTTP, rotas e códigos de status para deteção de tentativas de exploração.

### 2. Motores de Defesa e Automação (`scripts/`)
* **🛡️ Auditoria EDR (`edr_shadow_ai.sh`):** 
  - Deteta ferramentas de IA não autorizadas e chaves de API expostas.
  - Otimizado e calibrado para ignorar diretórios de sistema e caches ruidosas (`venv`, `.vscode`, `snap`, `.mozilla`), garantindo execuções limpas em menos de 1 segundo.
* **🌐 Threat Intelligence Proativa (`threat_intel.sh`):**
  - Descarrega diariamente as listas negras globais de ameaças da *Emerging Threats*.
  - Injeta proativamente os IPs maliciosos mais críticos diretamente no Firewall UFW.
  - **Automação:** Configurado para executar de forma totalmente silenciosa logo no arranque do sistema (`@reboot` via crontab).
* **📦 Cofre de Backups Imutáveis (`backup_imutavel.sh`):**
  - Compacta o código-fonte do SOC e os registos vitais (`fast.log`, `access.log`, relatórios EDR) num arquivo seguro `.tar.gz`.
  - **Blindagem de Segurança:** Aplica o atributo de imutabilidade do Linux (`chattr +i`) ao ficheiro gerado, tornando-o indestrutível mesmo para utilizadores com privilégios de *root* (proteção absoluta contra *ransomware*).
* **🔔 Alerta Móvel / Desktop (`alerta_soc.sh`):**
  - Monitoriza em tempo real o registo do Fail2Ban (`/var/log/fail2ban.log`).
  - Dispara notificações críticas visuais no ambiente de trabalho (`notify-send`) e envia um alerta detalhado via API de Bot do Telegram para o telemóvel do operador (com sistema de *debounce* de 60 segundos para evitar spam).

---

## 🔒 Segurança e Imutabilidade

Para evitar que softwares maliciosos ou ataques cibernéticos comprometam a integridade do sistema de defesa, os ficheiros vitais do SOC encontram-se rigorosamente trancados com o comando de imutabilidade do kernel Linux:
```bash
sudo chattr +i app.py edr_shadow_ai.sh threat_intel.sh backup_imutavel.sh alerta_soc.sh
