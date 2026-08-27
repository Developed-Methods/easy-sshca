#!/usr/bin/env bash

set -eu

SERVICE_USER="easy-sshca"
CA_DOMAIN="${1:?Usage: setup_server.sh <CA domain>}"
DATA_DIRECTORY="/home/${SERVICE_USER}/easy-sshca-data"
DATABASE_PATH="${DATA_DIRECTORY}/server.sqlite3"

if id -u "$SERVICE_USER" >/dev/null 2>&1; then
  echo "$SERVICE_USER already exists"
else
  sudo useradd "$SERVICE_USER"
fi

sudo mkdir -p "$DATA_DIRECTORY"

sudo curl -L -o /usr/local/bin/easy-sshca \
  https://github.com/Developed-Methods/easy-sshca/releases/latest/download/easy-sshca-amd64
sudo chmod +x /usr/local/bin/easy-sshca

if [ ! -f "$DATABASE_PATH" ]; then
  BOOTSTRAP_DIRECTORY="$(sudo mktemp -d "${DATA_DIRECTORY}/bootstrap.XXXXXX")"
  BOOTSTRAP_KEY="${BOOTSTRAP_DIRECTORY}/self-signed.key"
  BOOTSTRAP_CERT="${BOOTSTRAP_DIRECTORY}/self-signed.crt"

  sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
    -keyout "$BOOTSTRAP_KEY" \
    -out "$BOOTSTRAP_CERT" \
    -subj "/CN=${CA_DOMAIN}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "subjectAltName=DNS:${CA_DOMAIN}" \
    -batch

  sudo /usr/local/bin/easy-sshca init-server "$DATABASE_PATH" \
    --listen-addr 0.0.0.0:9292 \
    --tls-cert "$BOOTSTRAP_CERT" \
    --tls-key "$BOOTSTRAP_KEY"

  sudo rm "$BOOTSTRAP_KEY" "$BOOTSTRAP_CERT"
  sudo rmdir "$BOOTSTRAP_DIRECTORY"
fi

sudo tee "${DATA_DIRECTORY}/env" >/dev/null <<EOF
DATABASE_PATH=${DATABASE_PATH}
EOF

sudo chown -R "$SERVICE_USER" "/home/${SERVICE_USER}"

sudo tee /etc/systemd/system/easy-sshca.service >/dev/null <<EOF
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/easy-sshca start-server
Restart=always
User=${SERVICE_USER}
LimitNOFILE=1048576
LimitNOFILESoft=1048576
RestartSec=10
EnvironmentFile=${DATA_DIRECTORY}/env

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable easy-sshca
sudo systemctl start easy-sshca
