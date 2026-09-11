# easy-sshca

An SSH certificate authority with a server, admin CLI, and client in one executable.

Build and install on Linux with Rust, a C compiler, make, and Perl:

```sh
cargo install --path . --locked
```

Configure locked memory before running commands that load secrets. All commands except help and version require an unlimited memlock limit.
For a shell, have your administrator configure an unlimited hard memlock limit, then run `ulimit -l unlimited`.
For a systemd service, add this override:

```ini
[Service]
LimitMEMLOCK=infinity
LimitCORE=0
```

Allow `mlockall` and `prctl` in container or service syscall policies. Configure containers with unlimited soft and hard memlock limits.
The application refuses to load secrets when these protections fail.

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

## Secret memory and host storage

On Linux, startup disables process dumpability and verifies it before creating runtime threads or loading secrets.
It also checks that setting the core-file limit to zero succeeds.
Dumpability prevents kernel dumps sent to collectors, where `RLIMIT_CORE` alone does not apply.
See [Linux core dumps](https://www.man7.org/linux/man-pages/man5/core.5.html).

The application locks current and future process mappings, including Rust CA keys, parsing buffers, and signing stacks.
Pages become locked when accessed. This protection is independent of SQLCipher's memory controls.
The bundled SQLCipher build disables per-buffer locking, whose unlock calls could otherwise unlock shared heap pages.
SQLCipher memory wiping remains enabled. Build from the repository root to apply the required `.cargo/config.toml` settings.
An unlimited memlock limit prevents later allocations from exhausting a finite locking allowance.
Locked memory consumes physical RAM; size the host for the process workload.
See [Linux memory locking](https://www.man7.org/linux/man-pages/man2/mlockall.2.html).

Disable crash collection for the service in your host's collector configuration, including privileged diagnostic agents.
Encrypt or disable all swap storage. Disable hibernation or encrypt its image storage.
Memory locking does not prevent hibernation images, kernel crash dumps, or privileged host tools from capturing secrets.
Apply these requirements to hosts running administrative commands too, especially CA imports.
Review existing crash dumps, swap, and hibernation images under your secret-retention policy; these changes cannot remove earlier copies.

Library callers must call `memory::protect()` before reading secrets or starting secret-handling threads.
Database, server, and signing entry points also enforce protection before their own secret processing.
After protection, do not fork, change process credentials, or call memory-unlocking functions.
These operations can invalidate process protections.

Tests require the same unlimited memlock limit. With administrative access, run:

```sh
sudo prlimit --pid $$ --memlock=unlimited:unlimited
cargo test --locked
```
