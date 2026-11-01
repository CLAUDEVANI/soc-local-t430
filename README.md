# 🛡️ SOC Local (Centro de Operações de Segurança) - ThinkPad T430

Um Centro de Operações de Segurança (SOC) de nível empresarial (*Enterprise-Grade*) desenvolvido especificamente para ambiente local Linux (Ubuntu) no ThinkPad T430. O sistema integra monitorização em tempo real, deteção de intrusão, inteligência de ameaças proativa, auditoria EDR, backups forenses imutáveis e alertas locais.

---

## 🏗️ Arquitetura e Componentes do Sistema

O ecossistema divide-se em motores de infraestrutura em segundo plano e uma interface gráfica interativa desenvolvida em **Streamlit**.

### 1. Painel Visual de Controlo e Alertas (`app.py`)
* **Framework:** Streamlit (Layout em widescreen).
* **Métricas em Tempo Real:** Monitorização de recursos de hardware (CPU, RAM, Disco) via `psutil`, estado dos sensores operantes e contagem de ameaças ativas.
* **Geolocalização Offline:** Integração com a base de dados MaxMind GeoLite2 City (`.mmdb`) para mapear a origem geográfica dos IPs maliciosos.
* **Autenticação Opcional:** Defina a variável de ambiente `SOC_PASSWORD` para exigir senha no painel.
* **Abas de Análise Forense:**
  - **Suricata:** Registo de pacotes de rede suspeitos com filtragem avançada de ruído e parsing de IPv4/IPv6.
  - **Fail2Ban (Prisão UFW):** Monitorização dinâmica dos IPs bloqueados nos jails `suricata`, `sshd` e `nginx-botsearch`.
  - **Nginx (WAF):** Registo de acessos web, métodos HTTP, rotas e códigos de status para deteção de tentativas de exploração.

### 2. Motores de Defesa e Automação
* **🛡️ Auditoria EDR (`edr_shadow_ai.sh`):** 
  - Deteta ferramentas de IA não autorizadas e chaves de API expostas.
  - Otimizado e calibrado para ignorar diretórios de sistema e caches ruidosas (`venv`, `.vscode`, `snap`, `.mozilla`), garantindo execuções limpas em menos de 1 segundo.
* **🌐 Threat Intelligence e Geo-Blocking (`atualizar_geoblock.sh`):**
  - Configura o IPSet no nível do kernel para descartar pacotes silenciosamente no UFW (`before.rules`).
  - Descarrega e bloqueia zonas geográficas de alto risco.
  - Injeta proativamente a lista negra global da FireHOL (Level 1).
  - **Automação:** Agendado via Crontab para atualização diária às 04h00.
* **📦 Cofre de Backups Imutáveis (`backup_imutavel.sh`):**
  - Compacta o código-fonte do SOC e os registos vitais (`fast.log`, `access.log`, relatórios EDR) num arquivo seguro `.tar.gz`.
  - **Blindagem de Segurança:** Aplica o atributo de imutabilidade do Linux (`chattr +i`) ao ficheiro gerado, dificultando a alteração ou remoção por malware sem privilégios de *root*. Nota: um *root* ainda pode executar `chattr -i`; para proteção real contra *ransomware*, mantenha também uma cópia fora da máquina (outro disco, NAS ou nuvem com versionamento).

---

## 🔒 Segurança e Imutabilidade

Para evitar que softwares maliciosos ou ataques cibernéticos comprometam a integridade do sistema de defesa, os ficheiros vitais do SOC encontram-se rigorosamente trancados com o comando de imutabilidade do kernel Linux:
```bash
sudo chattr +i app.py atualizar_geoblock.sh edr_shadow_ai.sh backup_imutavel.sh
```