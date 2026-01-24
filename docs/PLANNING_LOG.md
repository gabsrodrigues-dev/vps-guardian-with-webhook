# Plan: VPS Guardian - Sistema de Proteção Anti-Cryptojacking

## Context

**Stack**: Python 3 + Shell Scripts + systemd
**Environment**: Execução Local em VPS Linux (Ubuntu/Debian)
**Paradigma**: Defesa em Profundidade (Prevenção → Detecção → Resposta → Auditoria)

**Problema**: VPS Linux comprometido múltiplas vezes por mineradores de criptomoedas (XMRig, perfctl malware).

**Solução**: Sistema multi-camadas que previne invasões, detecta comportamento anômalo, responde automaticamente e audita integridade do sistema.

---

## Estrutura de Arquivos Final

```
vps-guardian/
├── README.md                        # Documentação principal
├── setup.sh                         # Instalador orquestrador (idempotente)
├── config/
│   ├── sshd_hardened.conf          # Configuração SSH endurecida
│   ├── fail2ban.local              # Regras Fail2ban customizadas
│   └── tmp-mount.service           # Remount /tmp com noexec
├── firewall/
│   ├── rules.sh                    # Regras iptables persistentes
│   └── blocklists/
│       ├── mining-pools.txt        # Lista de IPs/domínios de pools
│       ├── tor-exit-nodes.txt      # Lista de exit nodes TOR
│       └── update-blocklist.sh     # Atualizador automático (via cron)
├── guardian/
│   ├── guardian.py                 # Script principal refatorado
│   ├── guardian.service            # systemd service unit
│   ├── config.yaml                 # Configuração centralizada
│   └── modules/
│       ├── __init__.py
│       ├── detector.py             # Detecção de processos suspeitos
│       ├── network.py              # Monitoramento de conexões
│       ├── integrity.py            # Verificação SHA256 de binários
│       ├── filesystem.py           # Watch de /tmp e /dev/shm
│       ├── resources.py            # Monitoramento temporal CPU/RAM (NOVO)
│       └── response.py             # Kill + quarentena + notificação
└── audit/
    ├── audit.sh                    # Wrapper para chkrootkit/rkhunter
    └── audit.cron                  # Crontab para verificações semanais
```

---

## Phases & Waves

### **WAVE 1: FUNDAÇÃO - Estrutura do Projeto**
**Objetivo**: Estabelecer arquitetura modular limpa e configuração base.

#### Passos:
- [ ] **1.1**: Criar estrutura de diretórios completa
  *Agent*: `backend-issue-worker`
  *Files*: Todos os diretórios conforme árvore acima

- [ ] **1.2**: Criar `config.yaml` com parâmetros centralizados
  *Agent*: `backend-issue-worker`
  *Conteúdo*:
  ```yaml
  detection:
    suspicious_terms: [xmrig, monero, moonre, miner, hashvault, ...]
    scan_interval_seconds: 5

  # Monitoramento de Recursos - LÓGICA SIMPLIFICADA
  # Premissa: Nenhum processo legítimo consome >75% por mais de 10 minutos
  resources:
    cpu_threshold_percent: 75
    memory_threshold_percent: 75
    notify_after_minutes: 10       # Notificar após 10 minutos de uso alto
    kill_after_minutes: 20         # MATAR após 20 minutos (sem exceção)
    vps_abuse_limit_minutes: 90    # Limite da VPS antes de bloqueio

    # Whitelist mínima (APENAS processos essenciais do sistema)
    whitelist:
      - dockerd
      - containerd
      - systemd
      - sshd
      - guardian.py                # O próprio guardian

  network:
    mining_pools_list: /root/vps-guardian/firewall/blocklists/mining-pools.txt
    tor_nodes_list: /root/vps-guardian/firewall/blocklists/tor-exit-nodes.txt

  response:
    quarantine_dir: /var/quarantine
    telegram_webhook: null  # Opcional
    log_file: /var/log/guardian.log

  integrity:
    critical_binaries: [/usr/bin/ps, /usr/bin/top, /bin/ls, /usr/bin/lsof]
    hash_db: /var/lib/guardian/hashes.json
  ```

- [ ] **1.3**: Migrar `sg.py` atual para `guardian/guardian.py` (refatorar imports)
  *Agent*: `backend-issue-worker`
  *Action*: Mover código existente, adicionar `import yaml`, estruturar `main()`

---

### **WAVE 2: PREVENÇÃO - Hardening do Sistema**
**Objetivo**: Fechar vetores de ataque conhecidos ANTES de começar monitoramento.

#### Passos:
- [ ] **2.1**: Criar `config/sshd_hardened.conf`
  *Agent*: `backend-issue-worker`
  *Configurações*:
  ```
  PermitRootLogin prohibit-password
  PasswordAuthentication no
  PubkeyAuthentication yes
  MaxAuthTries 3
  AllowUsers schubert  # Ajustar para usuário real
  ```

- [ ] **2.2**: Criar `config/fail2ban.local`
  *Agent*: `backend-issue-worker`
  *Regras*: Jail para SSH (bantime=1h, maxretry=3)

- [ ] **2.3**: Criar `config/tmp-mount.service`
  *Agent*: `backend-issue-worker`
  *Action*: systemd unit para remount `/tmp` e `/dev/shm` com `noexec,nosuid,nodev`

- [ ] **2.4**: Criar `firewall/blocklists/mining-pools.txt`
  *Agent*: `backend-issue-worker`
  *Source*: Integrar CoinBlockerLists (https://zerodot1.gitlab.io/CoinBlockerLists/hosts)

- [ ] **2.5**: Criar `firewall/blocklists/tor-exit-nodes.txt`
  *Agent*: `backend-issue-worker`
  *Source*: Lista pública de exit nodes TOR (https://check.torproject.org/exit-addresses)

- [ ] **2.6**: Criar `firewall/blocklists/update-blocklist.sh`
  *Agent*: `backend-issue-worker`
  *Action*: Script para baixar e atualizar listas automaticamente

- [ ] **2.7**: Criar `firewall/rules.sh`
  *Agent*: `backend-issue-worker`
  *Features*:
  - Carregar blocklists em ipset
  - Bloquear portas comuns de mining (3333, 8888, 14444)
  - Bloquear IPs das blocklists
  - Tornar regras persistentes (via iptables-persistent ou nftables)

---

### **WAVE 3: DETECÇÃO - Guardian Modular**
**Objetivo**: Refatorar `sg.py` em módulos especializados seguindo SOLID.

#### Passos:
- [ ] **3.1**: Criar `guardian/modules/detector.py`
  *Agent*: `backend-issue-worker`
  *Responsabilidade*: Detecção de processos suspeitos
  *Features*:
  - Manter lógica atual de termos suspeitos
  - Adicionar detecção por CPU anômalo (processos acima de threshold)
  - Adicionar detecção por padrões de nome (regex: `[random]`, `kworkerds`, etc.)
  - Adicionar detecção por caminho suspeito (`/tmp/`, `/dev/shm/`)

- [ ] **3.1.1**: Criar `guardian/modules/resources.py` (NOVO)
  *Agent*: `backend-issue-worker`
  *Responsabilidade*: Monitoramento temporal de CPU/Memória
  *Features*:
  - Manter histórico de uso de CPU/RAM por processo (dict com timestamps por PID)
  - Identificar processos que consomem >75% por tempo sustentado
  - **LÓGICA SIMPLIFICADA** (premissa: nenhum processo legítimo usa >75% por >10min):
    ```
    Timeline:
    ├── 0min:   CPU/RAM > 75% detectado → Início tracking
    ├── 10min:  Notificação Telegram enviada
    ├── 20min:  KILL IMEDIATO (sem exceção)
    └── 90min:  [LIMITE VPS - nunca chegaremos aqui]
    ```
  - Checar whitelist antes de matar (dockerd, systemd, sshd, guardian.py)
  - Retornar lista de processos para kill com tempo restante

- [ ] **3.2**: Criar `guardian/modules/network.py`
  *Agent*: `backend-issue-worker`
  *Responsabilidade*: Monitoramento de conexões de rede
  *Features*:
  - Verificar conexões ativas (psutil.net_connections())
  - Cruzar IPs remotos com mining-pools.txt e tor-exit-nodes.txt
  - Retornar PIDs de processos conectados a destinos suspeitos

- [ ] **3.3**: Criar `guardian/modules/integrity.py`
  *Agent*: `backend-issue-worker`
  *Responsabilidade*: Verificação de integridade de binários críticos
  *Features*:
  - Calcular SHA256 de binários listados em config.yaml
  - Comparar com hash_db.json (gerado no primeiro run)
  - Retornar lista de binários alterados (possível rootkit)

- [ ] **3.4**: Criar `guardian/modules/filesystem.py`
  *Agent*: `backend-issue-worker`
  *Responsabilidade*: Monitoramento de /tmp e /dev/shm
  *Features*:
  - Listar arquivos recém-criados (mtime < 5min)
  - Detectar executáveis em diretórios com noexec (bypasses)
  - Retornar caminhos suspeitos

- [ ] **3.5**: Criar `guardian/modules/response.py`
  *Agent*: `backend-issue-worker`
  *Responsabilidade*: Ações de resposta a incidentes
  *Features*:
  - Kill de processos (com parent kill se necessário)
  - Mover binários para quarentena
  - Gerar logs estruturados (JSON)
  - Enviar notificação Telegram (opcional via webhook)
  - **NOVO**: Níveis de resposta simplificados:
    ```python
    class ResponseLevel(Enum):
        NOTIFY = 1      # Notificar (10min de uso alto)
        KILL = 2        # Notificar + Kill imediato (20min OU trigger explícito)
    ```
  - **NOVO**: Notificação com contexto:
    ```
    🔔 [ALERTA] VPS Guardian
    ━━━━━━━━━━━━━━━━━━━
    Processo: suspicious_app (PID 12345)
    CPU: 85% por 10 minutos
    Memória: 45%
    Ação: NOTIFICANDO - Kill automático em 10 minutos
    ━━━━━━━━━━━━━━━━━━━

    ☠️ [KILL] VPS Guardian
    ━━━━━━━━━━━━━━━━━━━
    Processo: suspicious_app (PID 12345)
    CPU: 85% por 20 minutos
    Motivo: Uso sustentado acima do limite
    Ação: PROCESSO ELIMINADO
    ━━━━━━━━━━━━━━━━━━━
    ```

- [ ] **3.6**: Refatorar `guardian/guardian.py` (orquestrador)
  *Agent*: `backend-issue-worker`
  *Action*:
  - Carregar config.yaml
  - Importar todos os módulos
  - Loop principal com prioridades:
    ```
    1. detector.scan()       → Termos suspeitos (HARD_KILL)
    2. network.scan()        → Conexões p/ pools (HARD_KILL)
    3. integrity.check()     → Binários alterados (HARD_KILL + ALERTA CRÍTICO)
    4. filesystem.scan()     → Executáveis em /tmp (SOFT_KILL)
    5. resources.check()     → CPU/RAM sustentado (NOTIFY ou SOFT_KILL)
    ```
  - Consolidar ameaças e passar para response com nível adequado
  - **SIMPLIFICADO**:
    - 10min uso alto → NOTIFY (Telegram)
    - 20min uso alto → KILL (sem exceção)
    - Trigger explícito (termo/pool/rootkit) → KILL imediato
  - Manter função clean_zombies() do código original

---

### **WAVE 4: ORQUESTRAÇÃO - Setup Automatizado**
**Objetivo**: Tornar instalação trivial (`git clone && sudo ./setup.sh`).

#### Passos:
- [ ] **4.1**: Criar `setup.sh` (idempotente)
  *Agent*: `backend-issue-worker`
  *Features*:
  - Verificar distro (Ubuntu/Debian)
  - Instalar dependências: `python3-psutil`, `fail2ban`, `iptables-persistent`, `chkrootkit`, `rkhunter`
  - Copiar `config/sshd_hardened.conf` → `/etc/ssh/sshd_config.d/hardened.conf`
  - Copiar `config/fail2ban.local` → `/etc/fail2ban/jail.d/guardian.local`
  - Executar `firewall/rules.sh` e tornar persistente
  - Habilitar `config/tmp-mount.service`
  - Copiar `guardian/guardian.service` → `/etc/systemd/system/`
  - Criar diretórios: `/var/quarantine`, `/var/lib/guardian`
  - Gerar hash inicial de binários (`integrity.py --init`)
  - systemctl enable e start guardian.service
  - Configurar cron para update-blocklist.sh (diário)
  - Reiniciar SSH e fail2ban

- [ ] **4.2**: Criar `audit/audit.sh`
  *Agent*: `backend-issue-worker`
  *Action*: Wrapper para executar `chkrootkit` e `rkhunter --check --skip-keypress`

- [ ] **4.3**: Criar `audit/audit.cron`
  *Agent*: `backend-issue-worker`
  *Action*: Crontab entry para executar audit.sh semanalmente (domingo 2AM)

- [ ] **4.4**: Atualizar `guardian/guardian.service`
  *Agent*: `backend-issue-worker`
  *Melhorias*:
  ```ini
  [Unit]
  Description=VPS Guardian - Anti-Cryptojacking Protection
  After=network-online.target
  Wants=network-online.target

  [Service]
  Type=simple
  User=root
  WorkingDirectory=/root/vps-guardian/guardian
  ExecStart=/usr/bin/python3 /root/vps-guardian/guardian/guardian.py
  Restart=always
  RestartSec=5
  StandardOutput=journal
  StandardError=journal

  # Hardening
  NoNewPrivileges=true
  PrivateTmp=true

  [Install]
  WantedBy=multi-user.target
  ```

---

### **WAVE 5: DOCUMENTAÇÃO E TESTES**
**Objetivo**: Garantir que qualquer pessoa consiga usar e entender o sistema.

#### Passos:
- [ ] **5.1**: Criar `README.md` completo
  *Agent*: `backend-issue-worker`
  *Seções*:
  - O que é o VPS Guardian
  - Como funciona (diagrama de camadas)
  - Instalação (`git clone` + `sudo ./setup.sh`)
  - Verificação (`systemctl status guardian`)
  - Configuração avançada (`config.yaml`)
  - Logs (`journalctl -fu guardian`)
  - Desinstalação
  - FAQ / Troubleshooting

- [ ] **5.2**: Criar testes básicos
  *Agent*: `backend-issue-worker`
  *Casos*:
  - Script que simula minerador (processo com nome 'xmrig')
  - Verificar se Guardian mata o processo em <10s
  - Verificar se binário vai para quarentena
  - Verificar se log de incidente é gerado

- [ ] **5.3**: Criar `CHANGELOG.md`
  *Agent*: `backend-issue-worker`
  *Action*: Documentar evolução de sg.py → VPS Guardian v1.0

---

## Ordem de Execução

```
WAVE 1 (Fundação)
  ↓
WAVE 2 (Prevenção)
  ↓
WAVE 3 (Detecção)
  ↓
WAVE 4 (Orquestração)
  ↓
WAVE 5 (Documentação)
```

**Critério de Sucesso Final**:
1. Clone do repositório em VPS limpa
2. Executar `sudo ./setup.sh`
3. Sistema fica protegido contra:
   - Invasão SSH (hardening + fail2ban)
   - Execução de malware em /tmp (noexec mount)
   - Comunicação com mining pools (firewall blocklist)
   - Comunicação via TOR (exit nodes bloqueados)
   - Mineradores conhecidos (detecção por termo)
   - Mineradores disfarçados (detecção por CPU + rede)
   - Rootkits (verificação de integridade + audit)
   - **NOVO**: Bloqueio da VPS por abuso (kill preventivo antes de 90min)
   - **NOVO**: Mineração noturna (auto-kill de madrugada)

---

## Decisions Log

### Arquiteturais:
- **Python vs Go/Rust**: Python escolhido por simplicidade e biblioteca `psutil` robusta (YAGNI).
- **iptables vs nftables**: iptables mantido para compatibilidade com distros antigas.
- **systemd vs cron para Guardian**: systemd escolhido por restart automático e integração com journald.

### Segurança:
- **Blocklists externas**: CoinBlockerLists tem alta taxa de atualização (diária).
- **Noexec em /tmp**: Pode quebrar scripts legítimos, mas é trade-off aceitável.
- **Root execution**: Guardian precisa de CAP_KILL e acesso a /proc, root é necessário.

### Operacionais:
- **Idempotência do setup.sh**: Permitir re-execução sem quebrar sistema (usar `cp --backup`).
- **Logs estruturados**: JSON facilita integração futura com SIEM.

### Monitoramento de Recursos (SIMPLIFICADO):
- **Threshold 75%**: Margem de segurança antes dos 80-90% típicos de miners.
- **Premissa do usuário**: "Não tenho nenhum processo que use recursos altos por mais de 10 minutos".
- **10min = Notificar**: Alerta via Telegram para awareness.
- **20min = Kill imediato**: Sem distinção dia/noite, sem exceções (exceto whitelist mínima).
- **Whitelist mínima**: Apenas dockerd, systemd, sshd, guardian.py - nada mais.

---

## Próximos Passos

**Delegação**:
1. Atribuir WAVE 1 ao `backend-issue-worker` → Criar estrutura de arquivos e config.yaml
2. Após confirmação, atribuir WAVE 2 → Hardening
3. Após confirmação, atribuir WAVE 3 → Refatoração modular
4. Após confirmação, atribuir WAVE 4 → Setup automatizado
5. Após confirmação, atribuir WAVE 5 → Documentação

**Handoff esperado de cada Agent**:
```
Status: Success
Files Modified: [lista de paths absolutos]
Public Interface: [novos módulos/funções exportadas]
Key Decisions: [1-liner sobre escolha técnica]
```

---

## Referências Técnicas

- **perfctl malware**: https://www.aquasec.com/blog/perfctl-malware-targeting-linux-servers/
- **CoinBlockerLists**: https://zerodot1.gitlab.io/CoinBlockerLists/
- **TOR Exit Nodes**: https://check.torproject.org/exit-addresses
- **Linux Hardening**: https://www.cisecurity.org/cis-benchmarks
- **psutil docs**: https://psutil.readthedocs.io/

---

**Planning Coordinator**: Ready to delegate WAVE 1 quando autorizado.
