# 🛡️ SOC Local - T430

Um Centro de Operações de Segurança (SOC) local, resiliente e de alta performance, desenvolvido em Python com **Streamlit**. Projetado especificamente para a monitorização autónoma em tempo real do tráfego de rede, auditoria de portas, bloqueios de firewall, acessos web e inspeção de endpoints no ambiente Lenovo ThinkPad T430 (Ubuntu).

---

## 🚀 Funcionalidades e Módulos Integrados

1. **Autenticação Avançada (Fail-Closed & 2FA TOTP):**
   * Acesso restrito em duas etapas obrigatórias: Palavra-passe protegida por hash seguro e Autenticação de Dois Fatores (TOTP) compatível com Google Authenticator.
   * Mecanismo robusto de proteção contra força bruta com bloqueio temporário de IPs (`MAX_FALHAS = 5`, `BLOQUEIO_SEGUNDOS = 300`) e auditoria detalhada de tentativas (`[SOC-AUTH]`).

2. **Suricata IDS/IPS (Tráfego de Rede):**
   * Monitorização contínua de pacotes a partir do ficheiro `fast.log`.
   * Enriquecimento geográfico de IPs externos via base de dados GeoIP2 MaxMind.
   * Filtros inteligentes integrados para ocultar ruído de rede comum (ex: pacotes STUN, checksums IPv6, retransmissões e tráfego corporativo de APT) e mascarar o tráfego de saída nativo da própria máquina.

3. **Fail2Ban & UFW (Prisão de Firewall):**
   * Controlo e contagem em tempo real de IPs hostis neutralizados através de múltiplas *jails* ativas (`endlessh`, `nginx-botsearch`, `recidive`, `soc-auth`, `sshd`, `suricata`, `ufw-honeypot`).

4. **Nginx WAF (Acessos Web):**
   * Registo e parsing otimizado das últimas tentativas de acesso aos serviços web locais, permitindo detetar padrões de varredura ou exploração de rotas.

5. **Rede & Inventário LAN (Nmap Integrado):**
   * Varredura periódica automatizada na sub-rede local (`192.168.15.0/24`) e nas portas de escuta do próprio T430 (`127.0.0.1`).
   * Consolidação dos resultados em inventário JSON estático para consulta instantânea sem sobrecarga de processamento no painel.

6. **Auditoria EDR: Shadow AI:**
   * Módulo integrado de inspeção e auditoria de segurança de processos e ficheiros críticos do sistema, com execução restrita ao utilizador `root` via `sudo` com validação prévia de permissões e integridade de diretórios.

7. **Painel de Saúde do Sistema:**
   * Verificação em tempo real da disponibilidade e do estado de leitura de todas as fontes de logs e serviços essenciais (`fail2ban`, `suricata`, `nginx`, `ssh`, `ufw`, `endlessh`).

---

## ⚡ Otimizações Técnicas e Arquitetura

* **Performance Otimizada (Zero CPU Spike):** Utilização de `@st.cache_data` (TTL reduzido) e `@st.fragment(run_every=10)` para atualizações assíncronas e suaves da interface sem reexecuções globais desnecessárias do script.
* **Segurança Operacional (Imutabilidade):** Ficheiros críticos do sistema operativo e de configuração (`app.py`, `soc_local.env`, scripts de suporte) blindados com atributos de segurança avançados (`chattr +i` e `+a`) para impedir adulterações por vectores de ataque.

---

## 🏗️ Estrutura e Diagrama de Funcionamento

O fluxo do SOC Local baseia-se num modelo desacoplado: os sensores do sistema escrevem nos logs e os timers do systemd executam tarefas agendadas (como o Nmap), enquanto o painel Streamlit atua estritamente em modo de **leitura otimizada e segura**.

```text
       [ DAEMON / SENSORES DO SISTEMA ]
  ┌─────────────────────────────────────────┐
  │ Suricata IDS  ──> /var/log/suricata/    │
  │ Fail2Ban      ──> /var/run/fail2ban/    │
  │ Nginx WAF     ──> /var/log/nginx/       │
  │ Systemd Timer ──> soc_nmap_scan.sh      │
  └────────────────────┬────────────────────┘
                       │ (Geração de logs e JSONs)
                       ▼
         ┌───────────────────────────┐
         │  Armazenamento / Ficheiros│
         │  - nmap_inventory.json    │
         │  - fast.log / access.log  │
         └─────────────┬─────────────┘
                       │
                       │ (Leitura segura com cache)
                       ▼
         ┌───────────────────────────┐
         │     Painel Streamlit      │
         │         (app.py)          │
         │  ┌─────────────────────┐  │
         │  │ Autenticação 2FA    │  │
         │  ├─────────────────────┤  │
         │  │ Abas de Monitoria   │  │
         │  │ (Suricata, F2B,     │  │
         │  │  Nginx, Rede, Saúde)│  │
         │  ├─────────────────────┤  │
         │  │ Módulo EDR Shadow AI│  │
         │  └─────────────────────┘  │
         └─────────────┬─────────────┘
                       │
                       ▼
              [ Utilizador / T430 ]



