## Easy SSH CA
A simple tool with a web server for running an SSH-CA with TOTP support.

```
usage guide to come eventually...
```

### Install self-signed certificate and setup nginx
```
# generate 10 year certificate
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout ./self-signed.key \
    -out ./self-signed.crt
```

### Manual sign request over CURL
```
curl -X POST http://localhost:1234/sign/jump_host_sea_1/playit_prod/plorio \
    -H 'Authorization: Api-Key: 12314j2k1l3j21kl' \
    --data "@./id_ed25519.pub" > id_ed25519-cert.pub
```

