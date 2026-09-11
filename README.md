# easy-sshca

An SSH certificate authority with a server, admin CLI, and client in one executable.

The client and admin CLI support Linux and macOS. Running the server requires Linux for process-wide memory locking.

Build and install with Rust, a C compiler, make, and Perl:

```sh
cargo install --path . --locked
```

## For users

Your administrator sends you a client configuration file. It contains your access token, so treat it as a secret.

### 1. Save the configuration

Save the file as `~/.config/easy-sshca/config.yaml`:

```sh
mkdir -p -m 700 ~/.config/easy-sshca
mv ~/alice.yaml ~/.config/easy-sshca/config.yaml
chmod 600 ~/.config/easy-sshca/config.yaml
```

easy-sshca reads this path by default. It refuses to read the file if other users can read or write it.

Note: to keep the file somewhere else, pass `--config PATH` to every command.

For CI, pipe a decrypted YAML or JSON configuration through stdin:

```sh
sops decrypt client.enc.yaml | easy-sshca --config - sign --force
```

`--config -` also works with server configurations. Relative paths resolve from the current working directory.
Input is limited to 1 MiB. The CLI does not save the supplied configuration.
Commands that rewrite configuration (`configure`, `rotate-token`, and `admin key rotate-admin`) require a file path.
Do not combine `--config -` with other stdin inputs, including `--totp-stdin`, `--secret-stdin`, or private-key imports from stdin.

### 2. Generate an SSH key

The CA signs Ed25519 keys only. If you already have an Ed25519 key, skip this step and use it.

To make a new key:

```sh
easy-sshca gen-key
```

This writes the private key to `~/.ssh/id_ed25519` and the public key to `~/.ssh/id_ed25519.pub`.

`gen-key` never overwrites. If either file exists, it stops with `key files already exist`.

`ssh-keygen` works too, and it can protect the private key with a passphrase:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

Note: a passphrase never reaches the CA. Signing reads the public key only.

### 3. Point the configuration at your public key

Add `public_key` under `defaults` in `~/.config/easy-sshca/config.yaml`:

```yaml
version: 1
server: https://ca.example.com:9443
api_key: esca_at_01a08de5-dfe3-70a9-8021-8d101078cbb5_...
defaults:
  zone: null
  public_key: ~/.ssh/id_ed25519.pub
  duration: 1h
```

Note: set `zone` to a zone name too, and you can run `easy-sshca sign` with no arguments.

### 4. Enroll a TOTP authenticator

Start the enrollment:

```sh
easy-sshca totp enroll
```

The command prints a QR code and the secret in text form. Scan the QR code with your authenticator app. Enter the six-digit code at the prompt to confirm.

After enrollment, every signing request asks for a code.

### 5. Sign your key

Request a certificate from the `production` zone:

```sh
easy-sshca sign production
```

Enter the TOTP code at the prompt. The command writes the certificate to `~/.ssh/id_ed25519-cert.pub`.

Now log in. OpenSSH sends the certificate with the key automatically:

```sh
ssh alice@host.example.com
```

The certificate expires after the duration in your configuration. Run `sign --force` to replace it.

## For server operators

### 1. Initialize the instance on your local machine

```sh
easy-sshca server init --name "My SSH CA" --folder ./my-ca
```

This creates three files in `./my-ca`:

- `ca.db`, the encrypted database
- `server.yaml`, the server configuration
- `admin.yaml`, your admin credential and the bootstrap secret

Keep `admin.yaml` on your local machine. Never copy it to the server.

### 2. Prepare the server configuration

Edit `./my-ca/server.yaml` for the real host. Set the database path and bind the listeners to all interfaces. Leave the `tls` block exactly as `server init` wrote it:

```yaml
version: 1
database: /var/lib/easy-sshca/ca.db
rpc_listen: 0.0.0.0:9443
https_listen: 0.0.0.0:9444
metrics_listen: 127.0.0.1:9445          # optional; loopback addresses only
tls:
  certificate_pem: |
    -----BEGIN CERTIFICATE-----
    ...                                # leave as generated
  private_key_pem: |
    -----BEGIN PRIVATE KEY-----
    ...                                # leave as generated
limits:
  request_bytes: 65536
  rpc_timeout: 10s
  database_queue: 128
```

### 3. Copy the database and configuration to the server

The database is encrypted with the bootstrap secret, which stays on your local machine:

```sh
ssh root@ca.example.com 'mkdir -p -m 700 /var/lib/easy-sshca /etc/easy-sshca'
scp ./my-ca/ca.db root@ca.example.com:/var/lib/easy-sshca/ca.db
scp ./my-ca/server.yaml root@ca.example.com:/etc/easy-sshca/server.yaml
```

Start the server on the host:

```sh
easy-sshca server start --config /etc/easy-sshca/server.yaml
```

The server starts locked. Every operation except `unlock` fails, and `/health/ready` reports `locked`.

### 4. Point the admin configuration at the server

Edit `./my-ca/admin.yaml` and change `server` to your CA address. Leave `tls_ca_pem` in place; it is how the client trusts the server certificate:

```yaml
version: 1
server: https://ca.example.com:9443
api_key: esca_ad_01a08de5-b018-7398-8cda-6c5d3fb62caf_...
bootstrap_secret: QVYcKDvuJZhYW3j8dt9vPxA6GRglTeXujc9iLowfu8o
tls_ca_pem: |
  -----BEGIN CERTIFICATE-----
  ...                                  # leave as generated
defaults:
  zone: null
  public_key: null
  duration: null
```

The init certificate is a self-signed leaf. The client pins its public key, so changing the server address does not require reissuing it.

With a CA-issued server certificate, put the issuing CA certificate bundle in `tls_ca_pem` or `tls_ca`.
The client verifies the certificate chain, validity, and server name.
Only a single self-signed leaf enables public-key pinning; CA certificates and bundles use hostname verification.

For port forwarding with a CA-issued certificate, set `tls_server_name` to the name on that certificate:

```yaml
server: https://localhost:9443
tls_server_name: ca.example.com
```

This override also applies when using native roots without `tls_ca` or `tls_ca_pem`.
Forward the port with:

```sh
ssh -L 9443:localhost:9443 ca.example.com
```

### 5. Unlock the server

```sh
easy-sshca --config ./my-ca/admin.yaml server unlock
```

The command sends the bootstrap secret from `admin.yaml`. The server derives the database key and holds it in memory only.

CAUTION: repeat this step after every server restart. A restarted server stays locked and signs nothing until you unlock it.

### 6. Create the first zone

A zone owns one CA key. Create one called `production`:

```sh
easy-sshca --config ./my-ca/admin.yaml admin zone add production --max-duration 1d
```

Print the zone's CA public key:

```sh
easy-sshca --config ./my-ca/admin.yaml pub-key production
```

Install that key on every SSH host and point `TrustedUserCAKeys` at it. See [TrustedUserCAKeys and AuthorizedPrincipalsFile](https://man.openbsd.org/sshd_config#TrustedUserCAKeys). Hosts can also fetch it from `https://ca.example.com:9444/zones/production/ca.pub`.

### 7. Create the first user and access token

Add the user, grant zone access, and export a client configuration:

```sh
easy-sshca --config ./my-ca/admin.yaml admin user add alice --max-duration 1d
easy-sshca --config ./my-ca/admin.yaml admin user zone grant alice production
easy-sshca --config ./my-ca/admin.yaml admin access-token add \
  --user alice --name laptop --max-duration 1h -o alice.yaml
```

`alice.yaml` holds the server address, the access token, and the TLS trust certificate. Use a `.json` filename to export JSON instead.

The username becomes the certificate principal. Each SSH host needs an account named `alice`.

### 8. Deliver the configuration

WARNING: never send `alice.yaml` in plain text. Anyone who reads the file can request certificates as that user.

Encrypt the file before you send it, or use a secret manager. For example, with `age`:

```sh
age -R alice_age.pub -o alice.yaml.age alice.yaml
```

Delete your copy after delivery. To revoke a leaked token, run `admin access-token remove --user alice --name laptop`.

## Importing an existing CA

To reuse an existing Ed25519 SSH CA, import its unencrypted OpenSSH private key instead of running `zone add`:

```sh
easy-sshca --config ./my-ca/admin.yaml admin zone import production --file ./existing_ca
# Or read the key from stdin:
easy-sshca --config ./my-ca/admin.yaml admin zone import production --stdin < ./existing_ca
```

Import creates a new zone and preserves the CA fingerprint. It never replaces an existing zone.

Each CA key can belong to only one zone, including inactive zones. Changing a key's comment does not create a new CA identity.

Remove a zone and revoke all of its user grants with `easy-sshca --config ./my-ca/admin.yaml admin zone remove production`. Removal preserves certificate history and prevents the CA key from being imported again.

Before importing, inventory every host that already trusts the CA. Treat those hosts as part of the zone's access scope. OpenSSH enforces CA trust and principals, not this application's zone names. Use a fresh CA key when hosts require separate access scopes.

### Metrics and audit retention

Metrics are disabled unless `metrics_listen` is configured. Scrape `http://127.0.0.1:9445/metrics` locally when using the example configuration.
The public HTTPS listener does not serve `/metrics`.

The encrypted database retains the newest 10,000 audit events in insertion order.
Older events are deleted after each audit write and when the database opens.
Malformed credentials produce `MALFORMED_CREDENTIAL` events with empty actor fields.
Export audit events before eviction if you need longer retention.

Rate limits group IPv6 sources by /64. IPv4-mapped addresses share limits with their IPv4 equivalents.
When the 10,000-bucket table fills, new buckets replace the oldest buckets.
