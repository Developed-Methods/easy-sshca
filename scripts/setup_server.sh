USER="easy-sshca"
CA_DOMAIN="$1"

echo "Gen for ${CA_DOMAIN}";

if id -u $USER >/dev/null 2>&1; then
  echo "$USER already exists";
else
  sudo useradd $USER
  sudo mkdir -p /home/$USER/easy-sshca-data
  sudo mkdir -p /home/$USER/easy-sshca-data/totp
  sudo mkdir -p /home/$USER/easy-sshca-data/ca
  sudo mkdir -p /home/$USER/easy-sshca-data/api

  sudo tee /home/$USER/easy-sshca-data/config.yml <<EOF
listen_addr: 0.0.0.0:9292
users: []
targets: []
paths:
 root: /home/$USER/easy-sshca-data
 tls_crt: /home/$USER/easy-sshca-data/self-signed.crt
 tls_key: /home/$USER/easy-sshca-data/self-signed.key
EOF
  sudo tee /home/$USER/easy-sshca-data/env <<EOF
CONFIG_PATH=/home/$USER/easy-sshca-data/config.yml
EOF
fi

if [ ! -f /home/$USER/easy-sshca-data/self-signed.key ]; then
  sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
      -keyout /home/$USER/easy-sshca-data/self-signed.key \
      -out /home/$USER/easy-sshca-data/self-signed.crt \
      -subj "/CN=${CA_DOMAIN}" \
      -addext "basicConstraints=critical,CA:FALSE" \
      -addext "subjectAltName=DNS:${CA_DOMAIN}" \
      -batch
fi

sudo chown -R $USER /home/$USER

sudo curl -L -o /usr/local/bin/easy-sshca https://github.com/Developed-Methods/easy-sshca/releases/latest/download/easy-sshca-amd64
sudo chmod +x /usr/local/bin/easy-sshca

sudo tee /etc/systemd/system/easy-sshca.service <<EOF
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/easy-sshca start-server
Restart=always
User=$USER
LimitNOFILE=1048576
LimitNOFILESoft=1048576
RestartSec=10
EnvironmentFile=/home/$USER/easy-sshca-data/env

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable easy-sshca
sudo systemctl start easy-sshca
