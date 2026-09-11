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
Each CA key can belong to only one zone, including inactive zones. Changing a key's comment does not create a new CA identity.

Before importing, inventory every host that already trusts the CA. Treat those hosts as part of the zone's access scope.
Certificates contain the authenticated username as their principal. OpenSSH enforces CA trust and principals, not this application's zone names.
See [TrustedUserCAKeys and AuthorizedPrincipalsFile](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).
Use a fresh CA key when hosts require separate access scopes.

Before upgrading an existing deployment, run `--json admin zone list` with the current version and compare every zone's fingerprint.
Include inactive zones and follow all pagination tokens. Resolve repeated fingerprints before deployment.
Replace shared CAs with distinct keys and update host trust and user grants for each intended scope.
The application cannot replace a zone's CA; create replacement zones with fresh keys.
Remove shared CA trust from affected hosts; disabling a zone does not invalidate certificates already issued.

On unlock, the server checks existing CA identities and transactionally adds unique public-key and fingerprint indexes.
Duplicate CAs stop unlock with `DUPLICATE_CA`, identifying the conflicting zones and fingerprint. The database remains unchanged.
Inactive duplicates also require repair; disabling them cannot restore isolation.
Back up the encrypted database before offline repair of legacy duplicate zones.
Preserve issuance and audit records when repairing zone identities and coordinating host trust changes.

Give `alice.yaml` to the user securely. It includes the access token and TLS trust certificate.
Use a `.json` filename to export JSON instead.

As the user, generate an SSH key and request a certificate:

```sh
easy-sshca gen-key --file ./alice_ed25519
easy-sshca --config alice.yaml sign production --file ./alice_ed25519.pub
```

SSH hosts must trust the zone's CA through `TrustedUserCAKeys` and have an account matching the username.
Use `--help` on any command for more options.
