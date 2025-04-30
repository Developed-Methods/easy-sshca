## Easy SSH CA
A simple server and client to use ssh certificates


### Manual sign request over CURL
```
curl -X POST http://localhost:9090/sign/jump_host_sea_1/playit_prod/plorio \
    -H 'Authorization: Api-Key: 12314j2k1l3j21kl' \
    --data "@./id_ed25519.pub" > id_ed25519-cert.pub
```

### Install self-signed certificate and setup nginx
```
sudo apt update
sudo apt install nginx

# generate 10 year certificate
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/nginx/self-signed.key -out /etc/nginx/self-signed.crt

sudo tee /etc/nginx/sites-enabled/easy-ssh-ca.conf <<EOF
server {
    listen 9292 ssl;
    listen [::]:9292 ssl;

    ssl_certificate     /etc/nginx/self-signed.crt;
    ssl_certificate_key /etc/nginx/self-signed.key;

    location / {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:9290;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 310s;
        proxy_buffering off;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Origin "\${scheme}://\${host}";
        proxy_set_header Host "\${host}";
    }
}
EOF
```
