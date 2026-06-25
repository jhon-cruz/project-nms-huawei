# Huawei NMS Control

Sistema web para inventario, monitoramento e operacao assistida de equipamentos Huawei via SSH e SNMP.

## Instalacao no Ubuntu Server

Base recomendada: Ubuntu Server 26.04 LTS.

Execute no servidor:

```bash
curl -fsSL https://raw.githubusercontent.com/jhon-cruz/project-nms-huawei/main/scripts/install_ubuntu.sh -o install_nms_huawei.sh
sudo bash install_nms_huawei.sh
```

O instalador clona este repositorio em `/opt/project-nms-huawei`, cria um ambiente Python isolado, instala dependencias do sistema, configura o servico `project-nms-huawei` no `systemd` e publica a aplicacao em `http://IP_DO_SERVIDOR:8000`.

Comandos uteis:

```bash
sudo systemctl status project-nms-huawei
sudo journalctl -u project-nms-huawei -f
sudo systemctl restart project-nms-huawei
```

## Atualizacao

Durante o desenvolvimento, as atualizacoes sao feitas a partir deste repositorio.

Pela interface: entre como administrador, abra `Sistema` e clique em `Baixar atualizacao e reiniciar`.

Pelo terminal do servidor:

```bash
cd /opt/project-nms-huawei
sudo -u nms-huawei git pull --ff-only
sudo -u nms-huawei .venv/bin/pip install -r requirements.txt
sudo systemctl restart project-nms-huawei
```

## Hardware recomendado para 20 equipamentos

Para gerenciar cerca de 20 equipamentos simultaneamente com polling SNMP, testes SSH, consultas BRAS/BNG e auditoria local:

- Minimo funcional: 2 vCPU, 4 GB RAM, 40 GB SSD.
- Recomendado: 4 vCPU, 8 GB RAM, 80 GB SSD.
- Folga para novas funcionalidades, historico maior e coletas mais frequentes: 4 a 8 vCPU, 16 GB RAM, 120 GB SSD.

Use rede cabeada estavel entre o servidor NMS e os equipamentos. Para SNMP em muitos equipamentos, comece com intervalo de 60 segundos e reduza apenas depois de observar CPU, latencia e tempo total de coleta.

## Desenvolvimento local

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Abra `http://localhost:8000`.

## Estrutura

- `app/`: backend FastAPI, SSH, SNMP, storage e auditoria.
- `static/`: interface web.
- `scripts/install_ubuntu.sh`: instalador automatizado para Ubuntu Server.
- `data/`: banco SQLite local da instalacao, ignorado pelo Git.

## Observacoes de seguranca

O sistema possui autenticacao propria, armazena credenciais de equipamentos criptografadas localmente e registra acoes sensiveis em auditoria. Em producao, publique a interface atras de HTTPS e restrinja acesso de rede ao servidor.
