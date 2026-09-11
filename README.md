# easy-sshca

An SSH certificate authority with a server, admin CLI, and client in one executable.

Build and install on Linux with Rust, a C compiler, make, and Perl:

```sh
cargo install --path . --locked
```

Initialize a new folder and start the server:

```sh
easy-sshca server init --name "My SSH CA" --folder ./my-ca
easy-sshca server start --config ./my-ca/server.yaml
```

In another terminal, unlock it:

```sh
easy-sshca --config ./my-ca/admin.yaml server unlock
```

Repeat the unlock after each server restart. Keep `admin.yaml` private because it contains the admin key and bootstrap secret.
The generated server listens on localhost. For remote access, update the listener addresses, server URL, and TLS certificates.

Configuration values can use inline content or external files:

- Client and admin configs accept `api_key` or `api_key_file`.
- Admin configs accept `bootstrap_secret` or `bootstrap_secret_file`.
- Client and admin configs accept `tls_ca_pem` or `tls_ca`.
- Server configs accept `tls.certificate_pem` or `tls.certificate`.
- Server configs accept `tls.private_key_pem` or `tls.private_key`.

Do not configure both forms of the same value.

Create a zone and user, grant access, and save a portable client configuration:

```sh
easy-sshca --config ./my-ca/admin.yaml admin zone add production
easy-sshca --config ./my-ca/admin.yaml admin user add alice
easy-sshca --config ./my-ca/admin.yaml admin user zone grant alice production
easy-sshca --config ./my-ca/admin.yaml admin access-token add \
  --user alice --name laptop --max-duration 1h -o alice.yaml
```

To reuse an existing Ed25519 SSH CA, import its unencrypted OpenSSH private key instead of running `zone add`:

```sh
easy-sshca --config ./my-ca/admin.yaml admin zone import production --file ./existing_ca
# Or read the key from stdin:
easy-sshca --config ./my-ca/admin.yaml admin zone import production --stdin < ./existing_ca
```

Import creates a new zone and preserves the CA fingerprint. It never replaces an existing zone.

Give `alice.yaml` to the user securely. It includes the access token and TLS trust certificate.
Use a `.json` filename to export JSON instead.

As the user, generate an SSH key and request a certificate:

```sh
easy-sshca gen-key --file ./alice_ed25519
easy-sshca --config alice.yaml sign production --file ./alice_ed25519.pub
```

SSH hosts must trust the zone's CA through `TrustedUserCAKeys` and have an account matching the username.
Use `--help` on any command for more options.
