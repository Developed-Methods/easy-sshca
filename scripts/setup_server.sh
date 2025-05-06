USER="easy-sshca"
if id -u $USER 2>&1 /dev/null; then
  echo "$USER already exists";
else
  sudo useradd $USER
  sudo mkdir -p /home/$USER/easy-sshca-data
  sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
      -keyout /home/$USER/easy-sshca-data/self-signed.key \
      -out /home/$USER/easy-sshca-data/self-signed.crt
  sudo chown -R $USER /home/$USER
fi

sudo curl -o /usr/local/bin/easy-sshca https

sudo tee /etc/systemd/system/easy-sshca.service <<EOF
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
ExecStart={{ exec_start }}
Restart=always
User={{ user }}
LimitNOFILE=1048576
LimitNOFILESoft=1048576
{% if restart_sec is defined %}
RestartSec={{ restart_sec }}
{% else %}
RestartSec=10
{% endif %}
{% if exec_reload is defined %}
ExecReload={{ exec_reload }}
{% endif %}
{% if env_file_path is defined %}
EnvironmentFile={{ env_file_path }}
{% endif %}

{% if exec_start_pre is defined %}
ExecStartPre={{ exec_start_pre }}
{% endif %}

{% if exec_start_pre_list is defined %}
{% for cmd in exec_start_pre_list %}
ExecStartPre={{ cmd }}
{% endfor %}
{% endif %}

{% if exec_start_post is defined %}
ExecStartPost={{ exec_start_post }}
{% endif %}

{% if exec_stop is defined %}
ExecStop={{ exec_stop }}
{% endif %}

{% if log_file is defined %}
StandardOutput={{ log_file }}
{% if err_log_file is defined %}
StandardError={{ err_log_file }}
{% else %}
StandardError={{ log_file }}
{% endif %}
{% endif %}

[Install]
WantedBy=multi-user.target
EOF
