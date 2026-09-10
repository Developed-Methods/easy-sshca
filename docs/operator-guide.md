# Operating easy-sshca

## Install and initialize

Verify the release archive's checksum before extracting it.
Install the executable as `/usr/local/bin/easy-sshca`.
Create an unprivileged `easy-sshca` service account.
Initialize a new folder and assign it to the service account:

```sh
sudo easy-sshca server init \
  --name "Example SSH CA" --folder /var/lib/easy-sshca
sudo chown -R easy-sshca:easy-sshca /var/lib/easy-sshca
```

Initialization creates the folder and its three subfolders with mode 0700.
Files have mode 0600; the executable unlock script has mode 0700.
It refuses existing folders, including empty directories.

```text
my-ca/
  server/
    server.yaml
    ca.db
    ca.db.lock
    tls.crt
    tls.key
  client/
    config.yaml
    tls.crt
  admin/
    admin.yaml
    ca.admin-key
    ca.bootstrap-secret
    tls.crt
    unlock.sh
```

The server folder contains all runtime configuration and files.
The client folder contains no credentials.
Replace each `REPLACE_ME` in `client/config.yaml` with the server hostname, access-token key, zone, and public-key path.
The admin configuration contains the admin API key and a relative TLS trust path.
Each folder can be copied independently.

Initialization prints a start command and an unlock command.
Run the start command, then run the unlock command in another terminal.
The unlock script reads the bootstrap secret from its own directory and sends it through stdin.
It works from any current directory and after moving the admin folder.
It uses `easy-sshca` from PATH; set `EASY_SSHCA_BIN` to select another executable.

```sh
easy-sshca server start --config ./my-ca/server/server.yaml
# In another terminal:
./my-ca/admin/unlock.sh
```

The generated listeners use loopback ports 9443 and 9444.
The certificate covers `localhost`, `127.0.0.1`, and `::1`.
For remote access, change the listener addresses and provision a certificate for the server's DNS name.
Update both client configurations and their TLS trust files.
Keep the admin folder in protected operator storage, separate from the server folder and database backups.

An existing admin key can be supplied through `--admin-api-key-file`.
Initialization copies it into the new folder's credential file and admin configuration.
Its format is `esca_ad_<canonical-UUIDv7>_<32-random-bytes-as-unpadded-Base64url>`.
Access tokens use `esca_at` with the same identifier and secret encoding.
Bootstrap secrets contain 32 random bytes encoded as unpadded Base64url.

Partial files remain after initialization fails.
Inspect those files before retrying with a new folder.

Install `packaging/easy-sshca.service` into `/etc/systemd/system/`.
Its start command uses `/var/lib/easy-sshca/server/server.yaml`.
Adjust that path if you chose another folder.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now easy-sshca
```

The service starts locked.
Liveness returns 200, while readiness and CA-file requests return 503.
Administration and signing return gRPC `FAILED_PRECONDITION`.

## Unlock after every restart

Configure a client connection or provide `--server` and `--tls-ca` directly:

```sh
easy-sshca server status --server https://ca.example.com:9443
easy-sshca server unlock --server https://ca.example.com:9443 \
  --secret-stdin < /protected/operator/bootstrap-secret
```

For a private certificate authority, add `--tls-ca /path/to/root.pem`.
Otherwise, the client uses operating-system trust roots.
The client never disables TLS verification.
Unlock returns status only.
An admin key cannot unlock the database.

The server rejects concurrent unlock attempts and further unlocks after readiness.
Wrong secrets leave it locked.
Only local initialization and admin recovery can open the database outside the running server.
An advisory lock excludes simultaneous server and maintenance processes.

## Onboard a user

Create a separate administrator client configuration:

```sh
easy-sshca --config ~/.config/easy-sshca/admin.yaml configure \
  --server https://ca.example.com:9443 --api-key-stdin < /protected/admin-key

easy-sshca --config ~/.config/easy-sshca/admin.yaml admin zone add production --max-duration 1d
easy-sshca --config ~/.config/easy-sshca/admin.yaml admin user add alice --max-duration 1d
easy-sshca --config ~/.config/easy-sshca/admin.yaml admin user zone grant alice production
easy-sshca --config ~/.config/easy-sshca/admin.yaml admin access-token add \
  --user alice --name laptop --max-duration 1h
```

The final command prints the token's API key once.
To save a portable client configuration instead, supply `-o` or `--output`:

```sh
easy-sshca --config ~/.config/easy-sshca/admin.yaml admin access-token add \
  --user alice --name laptop --max-duration 1h --output alice.yaml
easy-sshca --config alice.yaml pub-key production
```

Use a `.json` filename for JSON; other filenames produce YAML.
The file contains the server URL, new API key, token duration default, and inline TLS trust when configured.
It does not copy the administrator's key, zone default, or local SSH key paths.
Select a zone when signing or add your own `defaults.zone`.
Output files use mode 0600 and existing files are refused.
With `--output`, stdout reports the saved path instead of the API key.
If installation fails after token creation, the error identifies a retained configuration or instructs you to revoke the token.
Transfer it through your approved secret channel.
Avoid recording that command's output in CI logs.
If creation succeeds but its response is lost, remove the token and create another.
The database stores only its secret digest.

As the user, configure the client:

```sh
easy-sshca configure --server https://ca.example.com:9443 --api-key-stdin --zone production
easy-sshca totp enroll
easy-sshca gen-key --comment alice@laptop
easy-sshca sign
```

Supply the access-token key through stdin or the hidden prompt.
Enrollment displays a terminal QR code and a selectable Base32 secret.
Confirm a six-digit code to activate TOTP.
Pending enrollments expire after ten minutes.
Starting another pending enrollment invalidates the previous pending secret.
Confirmed TOTP cannot be replaced through self-service.

The confirmation code is consumed by replay protection.
Wait for the next authenticator code before signing.
Signing requests another code when TOTP is enrolled.
TOTP is optional until enrollment succeeds.

For machine-readable enrollment, run `--json totp enroll`.
That command returns pending enrollment data without prompting for confirmation.
Complete it with `--json totp confirm --totp-stdin`.
Both commands emit exactly one JSON object.

## Client configuration

The default path is `$XDG_CONFIG_HOME/easy-sshca/config.yaml`.
Without `XDG_CONFIG_HOME`, it is `~/.config/easy-sshca/config.yaml`.
An explicit `--config` path takes precedence.
The client never searches the current directory.

```yaml
version: 1
server: https://ca.example.com:9443
api_key: esca_at_REPLACE_WITH_YOUR_COMPLETE_KEY
tls_ca: company-root.pem
defaults:
  zone: production
  public_key: ~/.ssh/id_ed25519.pub
  duration: 1h
```

Client configuration supports YAML and JSON (`.json` files).
For a configuration without a separate certificate file, replace `tls_ca` with `tls_ca_pem`:

```yaml
tls_ca_pem: |
  -----BEGIN CERTIFICATE-----
  REPLACE_WITH_PEM_CERTIFICATE_CONTENT
  -----END CERTIFICATE-----
```

Use either `tls_ca` or `tls_ca_pem`, not both.
Inline PEM may contain a certificate bundle.
Omit both fields for operating-system trust roots.
Token rotation preserves inline TLS and the configuration's YAML or JSON format.
Omit `api_key` for public CA discovery and status.
Relative file paths resolve against the configuration directory.
A leading `~/` expands to the home directory.
Unknown fields, duplicate keys, unsupported versions, and plaintext URLs are rejected.

Use `chmod 600` on client configuration files.
The client rejects group-readable or world-readable files and symbolic links.
`configure` creates private parent directories and saves the file atomically.
Replacing an existing configuration requires an interactive confirmation.

Command flags override configuration defaults.
Signing defaults to one day when no duration is configured.
Durations accept whole seconds through 365 days, including `30m`, `12h`, `1d`, and `1w`.
The effective duration is the minimum of the requested, zone, user, and token limits.
The certificate is backdated five minutes for clock skew.

Without a configured key, the client searches standard SSH public-key filenames.
Multiple matches require an explicit `--file` selection.
Only Ed25519 keys are accepted by the server.
`gen-key --file PATH` refuses to replace either key file.
`sign` writes `NAME-cert.pub` beside `NAME.pub`.
Use `--force` to replace an existing certificate.

## Credentials and permissions

Access tokens are permanently owned by one user.
The server derives the SSH principal from that user.
The caller cannot select another username.
Each token requires an explicit maximum duration at creation.
Names are unique within each user.

Use `admin zone update`, `admin user update`, and `admin access-token update` to change limits.
Those commands accept `--max-duration` and `--active true|false`.
Human-readable resource output uses labelled tables with names, readable durations, status, and token ownership.
Internal UUIDs are hidden by default.
Add `--verbose` (or `-v`) to show resource UUIDs and success request UUIDs.
The flag can appear before or after a subcommand.
Empty lists print `No results.`.
JSON output retains its existing fields, including UUIDs.
List commands support `--page-size` and `--page-token`.
Use `admin user zone list alice` to see Alice's granted zones, including disabled zones.
Grant and revoke with `admin user zone grant alice production` and `admin user zone revoke alice production`.
Pages contain at most 100 records.

```sh
easy-sshca admin access-token update --user alice --name laptop --max-duration 30m
easy-sshca admin user zone revoke alice production
easy-sshca admin access-token remove --user alice --name laptop
easy-sshca admin user totp clear alice
easy-sshca admin user remove alice
```

User removal disables all tokens and removes all grants.
Audit references remain as tombstones.
Removed usernames remain reserved; removed token names can be reused.
Removing credentials prevents future issuance.
Existing certificates and SSH sessions remain usable until their normal expiry.

## Rotate credentials safely

```sh
easy-sshca rotate-token
easy-sshca --config ~/.config/easy-sshca/admin.yaml admin key rotate-admin
```

Access-token rotation requires TOTP when enrolled.
Each command rotates only its authenticated credential.
Administrators cannot invoke the user's self-service rotation path.

The client saves a replacement key and request UUID before sending the RPC.
It also stages the complete replacement configuration with mode 0600.
After server confirmation, it atomically installs that configuration.
The previous key stops working when the server transaction commits.

If interrupted, rerun the same rotation command with the same configuration path.
The client reuses its `.rotation.yaml` recovery file and `.candidate.yaml` staged configuration.
Keep those protected files until recovery completes.
Do not manually restore an old key after confirmed rotation.
Retry records remain available for 24 hours.
After that window, recover a lost user credential through administrator removal and recreation.
An offline admin reset remains available for lost administrator credentials.

## Public CA distribution

The public trust route is `GET /zones/{name}/ca.pub`.
It returns an OpenSSH key, fingerprint-based ETag, and cache revalidation headers.
Unknown or disabled zones return 404.
Locked instances return 503 without cacheable trust data.

Fetch and install a key using its independently verified fingerprint:

```sh
scripts/install-trust.sh \
  https://ca.example.com:9444/zones/production/ca.pub \
  SHA256:EXPECTED_FINGERPRINT \
  /etc/ssh/easy-sshca/production-ca.pub
```

The script preserves the existing file if fetching or fingerprint verification fails.
Its optional fourth argument supplies a private TLS root.
Create the destination directory before running it.

Configure each host to trust only its intended zones:

```text
TrustedUserCAKeys /etc/ssh/easy-sshca/production-ca.pub
```

Validate the host configuration with `sshd -t` before reloading sshd.
Local account creation remains a provisioning responsibility.
The certificate principal must match the Unix login name.
Installed trust files keep existing hosts independent of CA availability.

## Backup, restore, and recovery

Stop the service before copying the encrypted database:

```sh
sudo systemctl stop easy-sshca
sudo cp --preserve=mode,ownership /var/lib/easy-sshca/server/ca.db /protected/backups/ca.db
sudo systemctl start easy-sshca
```

Unlock the restarted server with the matching bootstrap secret.
Never copy only a live database file.
Store the bootstrap secret separately from database backups.
Without that secret, the encrypted database is unrecoverable.

For restoration, stop the destination instance before installing the backup.
Restore ownership and mode 0600 before startup.
Unlock with the backup's matching secret.
Compare CA fingerprints, grants, user state, and credential state against the source instance.
Test signing before returning the restored service to use.

To replace a lost admin key, stop the service and run:

```sh
sudo -u easy-sshca easy-sshca server reset-admin \
  --db /var/lib/easy-sshca/server/ca.db \
  --secret-stdin --admin-output /protected/operator/recovered-admin-key
```

Supply the bootstrap secret on stdin.
The command writes a new protected credential before committing the reset.
It revokes previous admin credentials without changing CA keys.
Restart and unlock the server afterward.

## Limits, logging, and runtime protection

The server uses one SQLCipher connection on a dedicated worker thread.
A bounded queue serializes mutations, TOTP replay checks, and signing authorization.
Rollback journaling and in-memory temporary storage prevent decrypted database copies.
Startup verifies SQLCipher availability; unlock verifies decryption, integrity, foreign keys, and schema version.

The default RPC deadline is ten seconds.
Messages default to 64 KiB and responses are capped at 1 MiB.
Queue saturation returns `RESOURCE_EXHAUSTED`.
A timed-out mutation can have committed; retry its exact request UUID and payload.
Mutation retry records are bounded at 100,000 entries and expire after 24 hours.

Rate limits use source addresses and credential identifiers.
Unlock permits five attempts per source per minute.
Signing, TOTP confirmation, and token rotation permit ten requests per key per minute.
Source-wide traffic is capped at 300 requests per minute.
Credential-wide traffic is capped at 120 requests per minute.
Source addresses come from the direct connection, never forwarded headers.

The server uses `tracing` and `tracing-subscriber` to write JSON logs to stderr.
Startup logs report configuration loading, TLS loading, bound listener addresses, and the locked state.
A successful unlock logs the transition to READY.
Shutdown logs report the received signal and server stop.
RPC and public CA requests log successful outcomes at INFO, rejected requests at WARN, and internal or worker failures at ERROR.
RPC logs contain operation, validated request UUID, credential identifier, outcome, and latency.
Health and metrics polling do not produce request logs.
Authorization headers, bootstrap secrets, TOTP codes, and CA private keys are excluded.
The encrypted audit table records administrator mutations, self-service mutations, and signing outcomes.

HTTPS exposes `/health/live`, `/health/ready`, and `/metrics`.
Metrics include lock state, queue depth, request counts, failures, latency sums, and rate-limit rejections.
The issuance counter includes committed certificates and excludes idempotent retries.
It is restored from encrypted issuance records after unlock.

Run under the supplied unprivileged systemd unit.
Disable unencrypted swap or use encrypted swap.
The executable disables core dumps.
Keep server time synchronized for certificate validity and TOTP verification.
Encryption protects database files and backups, not a compromised running process.

## CLI and RPC errors

`--json` emits a versioned result or error object on stdout.
Human-readable progress and logs use stderr.
Enrollment secrets and newly created token keys appear only in their intentional success responses.
JSON error objects contain stable reason codes and request UUIDs, without secret input.

| Exit | Meaning |
| --- | --- |
| 1 | Unexpected failure |
| 2 | Invalid input or conflicting state |
| 3 | Authentication failure |
| 4 | Authorization failure |
| 5 | Service unavailable, locked, timed out, or exhausted |

RPC metadata carries `authorization: Bearer <key>`.
Mutations require canonical UUIDv7 request identifiers.
Responses include `x-request-id` metadata and the response's request identifier.
Errors encode `easysshca.v1.ErrorDetail` in gRPC status details.
Clients detect `TOTP_REQUIRED` through that typed detail.
One-time secret responses are never cached for retrieval.

## Verification and releases

```sh
cargo fmt --all -- --check
cargo test --locked
cargo test --locked --test ssh_login -- --ignored
cargo clippy --locked --all-targets -- -D warnings
scripts/check-supply-chain.sh
```

The SSH-login test requires `/usr/sbin/sshd` and a login-capable local account.
It starts an isolated loopback daemon and checks authentication before and after certificate expiry.
It does not modify the system SSH configuration.

Integration tests launch the actual TLS server process.
They cover locked boundaries, token authorization, restart, CA downloads, CLI signing, and interrupted rotation recovery.
Database tests cover encryption, restore, replay prevention, serial allocation, and transactional rollback.

Release CI builds native musl binaries for x86_64 and arm64.
It generates checksums, an SBOM, and archives containing configuration, systemd, and operator documentation.
Zone deletion, CA rotation, database rekeying, online backups, and immediate certificate revocation are deferred.

The audit configuration excludes RUSTSEC-2023-0071 for `ssh-key`'s optional, uncompiled RSA dependency.
The supply-chain check fails if any target enables that dependency.
All supported SSH keys and signatures use Ed25519.
