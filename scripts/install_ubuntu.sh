#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/jhon-cruz/project-nms-huawei.git}"
APP_DIR="${APP_DIR:-/opt/project-nms-huawei}"
APP_USER="${APP_USER:-nms-huawei}"
SERVICE_NAME="${SERVICE_NAME:-project-nms-huawei}"
APP_PORT="${APP_PORT:-8000}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root: sudo bash $0"
  exit 1
fi

echo "==> Instalando pacotes do Ubuntu"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  git \
  python3 \
  python3-venv \
  python3-pip \
  build-essential \
  snmp \
  openssh-client \
  sudo \
  ca-certificates

apt-get install -y snmp-mibs-downloader || true

if ! id -u "${APP_USER}" >/dev/null 2>&1; then
  echo "==> Criando usuario ${APP_USER}"
  useradd --system --create-home --shell /usr/sbin/nologin "${APP_USER}"
fi

if [[ -d "${APP_DIR}/.git" ]]; then
  echo "==> Atualizando codigo em ${APP_DIR}"
  if [[ -f "${APP_DIR}/data/nms.db" ]]; then
    cp "${APP_DIR}/data/nms.db" "${APP_DIR}/data/nms.db.bak.$(date +%Y%m%d%H%M%S)"
  fi
  git -C "${APP_DIR}" fetch --all --prune
  git -C "${APP_DIR}" pull --ff-only
else
  echo "==> Clonando ${REPO_URL} em ${APP_DIR}"
  rm -rf "${APP_DIR}"
  git clone "${REPO_URL}" "${APP_DIR}"
fi

echo "==> Preparando Python virtualenv"
cd "${APP_DIR}"
"${PYTHON_BIN}" -m venv .venv
.venv/bin/pip install --upgrade pip wheel
.venv/bin/pip install -r requirements.txt

mkdir -p "${APP_DIR}/data"
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"
chmod 750 "${APP_DIR}"

echo "==> Configurando sudo controlado para restart do servico"
cat > "/etc/sudoers.d/${SERVICE_NAME}" <<SUDOERS
${APP_USER} ALL=(root) NOPASSWD: /bin/systemctl restart ${SERVICE_NAME}, /usr/bin/systemctl restart ${SERVICE_NAME}
SUDOERS
chmod 440 "/etc/sudoers.d/${SERVICE_NAME}"

echo "==> Criando systemd service"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SERVICE
[Unit]
Description=Huawei NMS Control
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment=NMS_SERVICE_NAME=${SERVICE_NAME}
ExecStart=${APP_DIR}/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${APP_PORT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

SERVER_IP="$(hostname -I | awk '{print $1}')"
echo
echo "Instalacao concluida."
echo "Acesse: http://${SERVER_IP:-SEU_IP}:${APP_PORT}"
echo "Servico: systemctl status ${SERVICE_NAME}"
