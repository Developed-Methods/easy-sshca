# easy-sshca

An SSH certificate authority with a server, admin CLI, and client in one executable.

Build and install on Linux with Rust, a C compiler, make, and Perl:

```sh
cargo install --path . --locked
```

Initialize a new folder and start the server:

```sh
easy-sshca server init --name "My SSH CA" --folder ./my-ca
easy-sshca server start --config ./my-ca/server/server.yaml
```

In another terminal, unlock it:

```sh
./my-ca/admin/unlock.sh
```

Repeat the unlock after each server restart. Keep the `admin/` folder private; it contains credentials and the bootstrap secret.
The generated server listens on localhost. For remote access, update the listener addresses, server URL, and TLS certificates.

Create a zone and user, grant access, and save a portable client configuration:

```sh
easy-sshca --config ./my-ca/admin/admin.yaml admin zone add production
easy-sshca --config ./my-ca/admin/admin.yaml admin user add alice
easy-sshca --config ./my-ca/admin/admin.yaml admin user zone grant alice production
easy-sshca --config ./my-ca/admin/admin.yaml admin access-token add \
  --user alice --name laptop --max-duration 1h -o alice.yaml
```

To reuse an existing Ed25519 SSH CA, import its unencrypted OpenSSH private key instead of running `zone add`:

```sh
easy-sshca --config ./my-ca/admin/admin.yaml admin zone import production --file ./existing_ca
# Or read the key from stdin:
easy-sshca --config ./my-ca/admin/admin.yaml admin zone import production --stdin < ./existing_ca
```

Import creates a new zone and preserves the CA fingerprint. It never replaces an existing zone.

Give `alice.yaml` to the user securely. It includes the access token and TLS trust certificate.
Use a `.json` filename to export JSON instead.

As the user, generate an SSH key and request a certificate:

```sh
easy-sshca gen-key --file ./alice_ed25519
easy-sshca --config alice.yaml sign production --file ./alice_ed25519.pub
```

To use an existing RSA key, add its public key path to the client configuration:

```yaml
defaults:
  public_key: ~/.ssh/id_rsa.pub
```

Then request a certificate with `easy-sshca --config alice.yaml sign production`.
The certificate is saved beside the key as `id_rsa-cert.pub`. The private key stays on your machine.
Relative paths are resolved from the configuration directory. Paths starting with `~/` are resolved from your home directory.
The setting is optional; without it, the client searches `~/.ssh` for a single public key.
Use `sign --file PATH` to override the configured path for one request.
You can also save this setting when creating a configuration with `configure --public-key ~/.ssh/id_rsa.pub`.

SSH hosts must trust the zone's CA through `TrustedUserCAKeys` and have an account matching the username.
Use `--help` on any command for more options.
