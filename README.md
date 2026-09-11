# easy-sshca

An SSH certificate authority with a server, admin CLI, and client in one executable.

Build and install on Linux with Rust, a C compiler, make, and Perl:

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

### 2. Generate an SSH key

The CA signs Ed25519 keys only. Generate one:

```sh
easy-sshca gen-key
```

This writes the private key to `~/.ssh/id_ed25519` and the public key to `~/.ssh/id_ed25519.pub`.

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

Edit `./my-ca/server.yaml` for the real host. Bind the listeners to all interfaces and install a TLS certificate for your CA hostname:

```yaml
version: 1
database: /var/lib/easy-sshca/ca.db
rpc_listen: 0.0.0.0:9443
https_listen: 0.0.0.0:9444
tls:
  certificate: /etc/easy-sshca/tls.crt
  private_key: /etc/easy-sshca/tls.key
limits:
  request_bytes: 65536
  rpc_timeout: 10s
  database_queue: 128
```

Note: `server init` generates a self-signed certificate for `localhost` only. Replace it with a certificate for `ca.example.com`.

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

Edit `./my-ca/admin.yaml`. Change `server` to your CA address and delete the `tls_ca_pem` block:

```yaml
version: 1
server: https://ca.example.com:9443
api_key: esca_ad_01a08de5-b018-7398-8cda-6c5d3fb62caf_...
bootstrap_secret: QVYcKDvuJZhYW3j8dt9vPxA6GRglTeXujc9iLowfu8o
defaults:
  zone: null
  public_key: null
  duration: null
```

Note: delete `tls_ca_pem` only if a public authority issued your TLS certificate. For a private authority, replace its value with that authority's PEM certificate.

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

## Reference

### Configuration secrets

Every secret accepts inline content or an external file:

- Client and admin configurations accept `api_key` or `api_key_file`.
- Admin configurations accept `bootstrap_secret` or `bootstrap_secret_file`.
- Client and admin configurations accept `tls_ca_pem` or `tls_ca`.
- Server configurations accept `tls.certificate_pem` or `tls.certificate`.
- Server configurations accept `tls.private_key_pem` or `tls.private_key`.

Do not configure both forms of the same value.

### Importing an existing CA

To reuse an existing Ed25519 SSH CA, import its unencrypted OpenSSH private key instead of running `zone add`:

```sh
easy-sshca --config ./my-ca/admin.yaml admin zone import production --file ./existing_ca
# Or read the key from stdin:
easy-sshca --config ./my-ca/admin.yaml admin zone import production --stdin < ./existing_ca
```

Import creates a new zone and preserves the CA fingerprint. It never replaces an existing zone.

Each CA key can belong to only one zone, including inactive zones. Changing a key's comment does not create a new CA identity.

Before importing, inventory every host that already trusts the CA. Treat those hosts as part of the zone's access scope. OpenSSH enforces CA trust and principals, not this application's zone names. Use a fresh CA key when hosts require separate access scopes.

### Duplicate CA keys

On unlock, the server checks existing CA identities and transactionally adds unique public-key and fingerprint indexes. Duplicate CAs stop unlock with `DUPLICATE_CA`, identifying the conflicting zones and fingerprint. The database remains unchanged.

Before upgrading an existing deployment, run `--json admin zone list` with the current version and compare every zone's fingerprint. Include inactive zones and follow all pagination tokens. Resolve repeated fingerprints before deployment.

Replace shared CAs with distinct keys and update host trust and user grants for each intended scope. The application cannot replace a zone's CA; create replacement zones with fresh keys. Remove shared CA trust from affected hosts; disabling a zone does not invalidate certificates already issued.

Inactive duplicates also require repair; disabling them cannot restore isolation. Back up the encrypted database before offline repair of legacy duplicate zones. Preserve issuance and audit records when repairing zone identities and coordinating host trust changes.

Use `--help` on any command for more options.
