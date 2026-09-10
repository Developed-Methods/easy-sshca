# easy-sshca

An SSH certificate authority with named zones, user-owned access tokens, and self-service TOTP enrollment.
Each zone has an Ed25519 CA.
The server stores identities, credentials, CA keys, and issuance records in SQLCipher.
Every restart requires an operator to unlock the database over verified TLS.

The executable includes the server, administrator commands, and user client.
Tonic serves the versioned gRPC API on port 9443.
HTTPS serves public CA files and health endpoints on port 9444.
Signing uses `ssh-key` in memory.

Build and test on Linux:

```sh
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Native builds require a C compiler, make, and Perl.
SQLCipher, OpenSSL, and protoc are bundled.
Release builds target `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.

Start with the [operator guide](docs/operator-guide.md).
The [verification report](docs/verification.md) records the local checks.
The [implementation plan](docs/implementation-plan.html) records the design requirements.
The protobuf contract lives in [proto/easysshca/v1/ca.proto](proto/easysshca/v1/ca.proto).

```sh
easy-sshca server init --name "Example SSH CA" --folder ./my-ca
easy-sshca server start --config ./my-ca/server.yaml
easy-sshca --config ./my-ca/admin.yaml server unlock --secret-stdin < ./my-ca/ca.bootstrap-secret
```

Initialization creates a private folder containing the database, credentials, TLS files, and server and admin configurations.
It prints a start command using the generated configuration. Existing folders are refused.
The generated self-signed certificate covers localhost and loopback IP addresses; listeners bind to loopback.
For remote access, update the listener addresses and supply a certificate for the server hostname.

This is a replacement implementation with a new database schema, protocol, and configuration format.
It includes no migration or compatibility layer.
