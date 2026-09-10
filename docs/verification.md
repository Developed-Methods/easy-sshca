# Rebuild verification

Verified locally on 10 September 2026 with Rust 1.98.0.

| Check | Evidence |
| --- | --- |
| Core tests | 11 passing tests cover configuration, credentials, SQLCipher, restore, TOTP, signing, and idempotency. |
| Server integration | Five passing tests launch real TLS servers and exercise the CLI, RPC boundaries, HTTP, restart, and recovery. |
| OpenSSH login | An isolated sshd accepts a signed certificate and rejects it after expiry. |
| Contention | Queue overflow is rejected, deadlines expire, and expired queued mutations do not commit. |
| Crash recovery | Forced termination preserves encrypted state and certificate serial ordering. |
| Secret scans | Database files and server logs exclude known credentials and OpenSSH private-key markers. |
| Static analysis | Clippy passes with warnings denied; rustfmt and whitespace checks pass. |
| Dependencies | Advisory, license, dependency-ban, and source checks pass with the documented RSA exception. |
| Release builds | Optimized static musl executables build for x86_64 and aarch64. |
| Release smoke | Extracted archives pass initialization, verified TLS, unlock, administration, CA download, signing, rotation, and restart. |

The x86_64 executable runs natively.
The aarch64 executable runs under QEMU for the local release smoke test.
GitHub Actions is configured to build and test each musl target on its native architecture.
Hosted CI has not been invoked from this workspace.

Release archives, CycloneDX SBOMs, and SHA-256 checksum files are in `dist/`.
The release workflow regenerates these artifacts from the checked-out source.

RUSTSEC-2023-0071 concerns an optional RSA dependency recorded in Cargo.lock.
RSA is absent from the compiled dependency graph.
The supply-chain script rejects any future change that enables it.
SSH key generation and certificate signing support Ed25519 only.
