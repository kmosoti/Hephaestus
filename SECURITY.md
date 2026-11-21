# Security Policy

Hephaestus stores authoritative Jujutsu (`jj`) repository history, content-addressed `GRNB0002` bundles, SQLite WAL state, hash-chained Decision Logs, and orthogonal Observation Logs, and exposes an Ed25519 mTLS-pinned QUIC endpoint and HTTP compatibility bridge.

## Supported Versions

Hephaestus is in alpha (`0.1.0-alpha.1`). Only `main` and the latest alpha tag receive security fixes.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Latest `0.1.0-alpha.*` release | Yes |
| Older pre-releases | No |

## Reporting a Vulnerability

**Do not report vulnerabilities in public issues, discussions, or pull requests.**

Report privately through GitHub's [private vulnerability reporting](https://github.com/kmosoti/Hephaestus/security/advisories/new) for this repository.

Please include:

- The affected crate or boundary (`hephaestus-core`, `hephaestus-store`, `hephaestus-store-sqlite`, `hephaestus-store-object`, `hephaestus-jj`, `hephaestus-server`).
- The security impact (e.g., QUIC mTLS bypass, OAuth token/credential disclosure, `GRNB0002` decompression bomb/bounds bypass, hash-chain tampering, or idempotency replay violation).
- Minimal reproduction steps or a failing test case.

## Scope & Security Boundaries

In scope:

- Ed25519 mTLS certificate pinning in `hephaestus-server`.
- OAuth2 PKCE `drive.file` scope enforcement and `SecretString` redaction in `hephaestus-core` and `hephaestus-store-object`.
- Cryptographic hash-chain and BLAKE3 integrity verification across `GRNB0002` bundles, Decision Logs, Observation Logs, and LTX snapshots.

Out of scope:

- Compromised host kernels or local root attackers with direct write access to the SQLite state directory or TLS private key material.
- Upstream vulnerabilities in cloud object storage providers or Google Drive APIs.
