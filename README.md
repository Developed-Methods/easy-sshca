# Easy SSH CA

Easy SSH CA runs an SSH certificate authority with TOTP support.

The server stores its settings, identities, access rules, and secrets in one SQLite database. The client configuration remains in the user's configuration directory.

## Create a server database

Generate a TLS certificate and private key before initializing the database:

```sh
openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
  -keyout self-signed.key \
  -out self-signed.crt \
  -subj "/CN=sshca.example.com" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "subjectAltName=DNS:sshca.example.com" \
  -batch

easy-sshca init-server server.sqlite3 \
  --listen-addr 0.0.0.0:9292 \
  --tls-cert self-signed.crt \
  --tls-key self-signed.key
```

`init-server` copies the TLS certificate and key into SQLite. The server does not read those files afterward.

Configure users, clients, and targets with any SQLite client. This example uses the `sqlite3` command-line client:

```sql
PRAGMA foreign_keys = ON;

INSERT INTO clients (name, max_duration, api_key)
VALUES ('jump_host_sea_1', 'day', 'replace-with-a-random-secret');

INSERT INTO targets (
    name,
    max_duration,
    ca_private_key,
    ca_public_key
)
VALUES (
    'playit_prod',
    'day',
    CAST(readfile('playit_prod') AS TEXT),
    CAST(readfile('playit_prod.pub') AS TEXT)
);

INSERT INTO users (
    name,
    max_duration,
    allow_missing_totp,
    totp_secret
)
VALUES (
    'plorio',
    'day',
    0,
    CAST(readfile('plorio.totp') AS TEXT)
);

INSERT INTO user_clients (user_name, client_name)
VALUES ('plorio', 'jump_host_sea_1');

INSERT INTO user_targets (user_name, target_name)
VALUES ('plorio', 'playit_prod');
```

Valid durations are `minute`, `hour`, `day`, and `week`. Names may contain letters, numbers, underscores, and hyphens.

## Migrate an existing server

Import the existing server configuration and every referenced secret file:

```sh
easy-sshca import-server /etc/easy-sshca/config.yml /var/lib/easy-sshca/server.sqlite3
```

The destination database must not contain server settings. Keep the original files until you verify the imported database.

## Run the server

Pass the database path as an argument:

```sh
easy-sshca start-server /var/lib/easy-sshca/server.sqlite3
```

You can also set `DATABASE_PATH`:

```sh
DATABASE_PATH=/var/lib/easy-sshca/server.sqlite3 easy-sshca start-server
```

Changes to users, clients, targets, access rules, and their secrets apply to later requests. Restart the server after changing `listen_addr`, `tls_cert`, or `tls_key`.

## Manual signing request

```sh
curl -X POST https://sshca.example.com:9292/sign/jump_host_sea_1/playit_prod/plorio \
  -H 'Authorization: Api-Key: replace-with-a-random-secret' \
  --data '@./id_ed25519.pub' > id_ed25519-cert.pub
```
