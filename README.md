# 🛡️ SOC Local - T430

Um Centro de Operações de Segurança (SOC) local e interativo desenvolvido em Python com **Streamlit**. Projetado para monitorização em tempo real do tráfego de rede, bloqueios de firewall e acessos web no ambiente Lenovo ThinkPad T430 (Ubuntu).

## 🚀 Funcionalidades e Sensores Integrados
* **Suricata (Tráfego de Rede):** Monitorização de intrusões (IDS/IPS) com análise de IPs via GeoIP2.
* **Fail2Ban (Prisão UFW):** Controlo e visualização de IPs hostis bloqueados ativamente no firewall.
* **Nginx (Acessos Web):** Registo de acessos locais e análise de tráfego web/WAF.
* **EDR Shadow AI:** Módulo de auditoria de sistema executável via interface.
* **Autenticação 2FA:** Acesso restrito ao painel com palavra-passe e autenticação de dois fatores (TOTP / Google Authenticator).

## ⚡ Últimas Otimizações e Ajustes (v2.0)
O painel foi recentemente reestruturado para máxima eficiência e estabilidade:
* **Performance (Zero CPU Spike):** Implementação de cache em memória (`@st.cache_data` com TTL de 5s) nas funções de leitura de logs. Elimina a sobrecarga no disco e no processador durante as renderizações.
* **Atualização Assíncrona:** Integração do `streamlit_autorefresh` (intervalo de 5000ms) para leitura em tempo real sem interrupções visuais na interface.
* **Correções Estruturais:** Declaração global das constantes de dataframes (`COLUNAS_SURICATA`, `COLUNAS_F2B`, `COLUNAS_NGINX`) garantindo a integridade da interface mesmo com ficheiros de log vazios.
* **Segurança Reforçada (Imutabilidade):** Ficheiros críticos do sistema (`app.py` e `soc_local.env`) configurados com o atributo `chattr +i` no sistema operativo, impedindo modificações não autorizadas.
* **Git Habilitado:** Repositório alinhado via SSH, com proteção de dados sensíveis (`.env`, `venv/`, `__pycache__`, `*.log`) via `.gitignore`.

## 🛠️ Como Executar
1. Ative o ambiente virtual: `source venv/bin/activate`
2. Instale as dependências: `pip install -r requirements.txt`
3. Configure as variáveis de ambiente no ficheiro `.env` (protegido).
4. Inicie o serviço pelo Systemd ou via terminal:
