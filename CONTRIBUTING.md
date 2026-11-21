# Contributing to Hephaestus

Thank you for contributing to Hephaestus.

## Prerequisites

- Rust `1.100.0` (managed automatically via `rust-toolchain.toml`)
- Jujutsu (`jj`) and Git (`jj git init --colocate` compatible)

## Repository Workflow

Hephaestus uses a **single-branch `main`** model with **stacked Jujutsu (`jj`) pull requests**:

1. Keep `main` linear and protected via `.github/CODEOWNERS` (`* @kmosoti`).
2. Automated contributors (`@kennmosoti-maker`) open stacked pull requests using bookmarks named `stack/<topic>/01-<step>`, `02-<step>`, etc., so each layer can be reviewed and merged in sequence.
3. Never use `git push --force` to `main` or bypass CI checks.

## Architecture Overview

Hephaestus follows strict hexagonal boundaries enforced by `cargo xtask check-layers` and `cargo xtask check-core-purity`:

- `crates/core/hephaestus-core`: `#![no_std]` pure Sans-I/O algorithms (`GRNB0002` bundler, BLAKE3 CAS, token-bucket quota governor, PKCE OAuth2 FSM, hash-chained Decision Log, orthogonal Observation Log).
- `crates/ports/hephaestus-store`: Driven port traits (`ObjectBackend`, `CatalogStore`, `LogStore`, `WebhookSink`).
- `crates/adapters/*`: Concrete adapters (`hephaestus-store-sqlite`, `hephaestus-store-object`, `hephaestus-jj`).
- `crates/bin/*`: Composition root (`hephaestus-server`) and development tooling (`hephaestus-xtask`).

## Pre-PR Verification

Run the full gate suite locally before opening or updating stacked pull requests:

```sh
cargo fmt --all --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo xtask check-layers
cargo xtask check-core-purity
cargo xtask check-workflow-pins
```

## Coding Standards

- `#![forbid(unsafe_code)]` across the entire workspace.
- Document every public module, type, trait, and function (`missing_docs = "warn"`).
- Keep individual `.rs` files under `350` lines.
- Use Rust, Nix, or POSIX shell tools only (no Python).
- Use RFC 3849/4193 IPv6 documentation ranges (`2001:db8::/32`, `fd00:db8::/64`, `[::1]:0`) in examples and tests.

## Security & Licensing

- Report security issues privately per [SECURITY.md](SECURITY.md).
- Contributions are licensed under the [Apache License 2.0](LICENSE).
