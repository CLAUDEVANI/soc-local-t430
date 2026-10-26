# 🛡️ SOC Local (Centro de Operações de Segurança) - ThinkPad T430

Um Centro de Operações de Segurança (SOC) de nível empresarial (*Enterprise-Grade*) desenvolvido especificamente para ambiente local Linux (Ubuntu) no ThinkPad T430[cite: 8]. O sistema integra monitorização em tempo real, deteção de intrusão, inteligência de ameaças proativa, auditoria EDR, backups forenses imutáveis e alertas móveis via Telegram[cite: 8].

---

## 🏗️ Arquitetura e Componentes do Sistema

O ecossistema divide-se em motores de infraestrutura em segundo plano e uma interface gráfica interativa desenvolvida em **Streamlit**[cite: 8].

### 1. Painel Visual de Controlo e Alertas (`app.py`)
* **Framework:** Streamlit (Layout em widescreen)[cite: 8].
* **Métricas em Tempo Real:** Monitorização de recursos de hardware (CPU, RAM, Disco) via `psutil`, estado dos sensores operantes e contagem de ameaças ativas[cite: 8].
* **Geolocalização Offline:** Integração com a base de dados MaxMind GeoLite2 City (`.mmdb`) para mapear a origem geográfica dos IPs maliciosos[cite: 8].
* **Notificações Integradas:** Comunicação direta com a API do Telegram (`requests`) para enviar alertas em tempo real ao administrador sempre que uma nova ameaça é neutralizada, com memória de bloqueios para evitar *spam*.
* **Abas de Análise Forense:**
  - **Suricata:** Registo de pacotes de rede suspeitos com filtragem avançada de ruído e parsing de IPv4/IPv6[cite: 8].
  - **Fail2Ban (Prisão UFW):** Monitorização dinâmica dos IPs atualmente bloqueados pelo firewall[cite: 8].
  - **Nginx (WAF):** Registo de acessos web, métodos HTTP, rotas e códigos de status para deteção de tentativas de exploração[cite: 8].

### 2. Motores de Defesa e Automação
* **🛡️ Auditoria EDR (`edr_shadow_ai.sh`):** 
  - Deteta ferramentas de IA não autorizadas e chaves de API expostas[cite: 8].
  - Otimizado e calibrado para ignorar diretórios de sistema e caches ruidosas (`venv`, `.vscode`, `snap`, `.mozilla`), garantindo execuções limpas em menos de 1 segundo[cite: 8].
* **🌐 Threat Intelligence e Geo-Blocking (`atualizar_geoblock.sh`):**
  - Configura o IPSet no nível do kernel para descartar pacotes silenciosamente no UFW (`before.rules`).
  - Descarrega e bloqueia zonas geográficas de alto risco (Rússia e China).
  - Injeta proativamente a lista negra global da FireHOL (Level 1).
  - **Automação:** Agendado via Crontab para atualização diária às 04h00.
* **📦 Cofre de Backups Imutáveis (`backup_imutavel.sh`):**
  - Compacta o código-fonte do SOC e os registos vitais (`fast.log`, `access.log`, relatórios EDR) num arquivo seguro `.tar.gz`[cite: 8].
  - **Blindagem de Segurança:** Aplica o atributo de imutabilidade do Linux (`chattr +i`) ao ficheiro gerado, tornando-o indestrutível mesmo para utilizadores com privilégios de *root* (proteção absoluta contra *ransomware*)[cite: 8].

---

## 🔒 Segurança e Imutabilidade

Para evitar que softwares maliciosos ou ataques cibernéticos comprometam a integridade do sistema de defesa, os ficheiros vitais do SOC encontram-se rigorosamente trancados com o comando de imutabilidade do kernel Linux[cite: 8]:
```bash
sudo chattr +i app.py atualizar_geoblock.sh edr_shadow_ai.sh backup_imutavel.sh
