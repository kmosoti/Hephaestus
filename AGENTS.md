# AGENTS.md

Guidance for automated coding agents and contributors in Hephaestus. Human contributors should also read [CONTRIBUTING.md](CONTRIBUTING.md); both documents agree.

## Project

Hephaestus is a standalone, Apache-2.0 authoritative Jujutsu (`jj-lib`) storage and replication backend built in Rust `1.100.0`. It combines an Ed25519 mTLS-pinned QUIC transport (`quinn`), content-addressed `GRNB0002` Zstd bundling over Apache Arrow `object_store` (LocalFS/S3/R2/GCS) and native-IPv6 `GoogleDriveStore` (`drive.file`), `rusqlite` WAL (`page_size = 16384`) idempotency and Zstd LTX snapshots, a hash-chained Decision Log, and orthogonal Observation Logs keyed by `jj` `ChangeId`, `CommitId`, and `OpId`.

## Source of Truth

| Topic | Document |
| --- | --- |
| Architecture and crate layers | [docs/adr/0000-foundations.md](docs/adr/0000-foundations.md) |
| Core purity policy | [crates/core/PURITY.toml](crates/core/PURITY.toml) |
| Security boundary | [SECURITY.md](SECURITY.md) |

## Verification Commands

The Rust toolchain is pinned to `1.100.0` in `rust-toolchain.toml`.

```sh
cargo fmt --all --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo xtask check-layers
cargo xtask check-core-purity
cargo xtask check-workflow-pins
```

All checks must pass with `--locked` before a commit is ready for review.

## Hexagonal Layout

| Path | Layer | Allowed Workspace Dependencies |
| --- | --- | --- |
| `crates/core/` | Domain (`hephaestus-core`) | None (`#![no_std]` + `alloc`, pure Sans-I/O) |
| `crates/ports/` | Driven ports (`hephaestus-store`) | `core/` only |
| `crates/adapters/` | Driven adapters (`hephaestus-store-sqlite`, `hephaestus-store-object`, `hephaestus-jj`) | `core/` and `ports/` only |
| `crates/bin/` | Composition roots & tooling (`hephaestus-server`, `hephaestus-xtask`) | Any non-`bin/` workspace crate |

## Branching & Stacked `jj` Workflow

- **Single-branch `main`:** `main` is protected by native GitHub branch rulesets requiring passing CI checks, linear history, and approval from `@kmosoti` (`.github/CODEOWNERS`).
- **Agent identity (`@kennmosoti-maker`):** Automated contributors operate as Write-only collaborator `@kennmosoti-maker` using colocated Jujutsu (`jj git init --colocate`) and isolated `jj workspace add` working trees. Agents never push directly to `main` or self-approve pull requests.
- **Stacked `jj` PRs:** Organize changes as small, focused commits with stacked bookmarks (`stack/<topic>/01-...`, `02-...`, ...). Every commit in the stack must build and pass `cargo xtask` checks independently.

## Hard Rules

1. **Zero Python:** Never add Python in source files, build tooling, tests, Nix derivations, or CI commands. Use Rust, Nix, or POSIX shell utilities (`rg`, `jq`, `curl`, `wc`).
2. **Rust `1.100.0`, Edition 2024, `resolver = "3"`:** Keep all crates aligned with workspace lints (`unsafe_code = "forbid"`, `missing_docs = "warn"`).
3. **Pure `hephaestus-core`:** `crates/core/hephaestus-core` MUST remain `#![no_std]` with zero filesystem, network, wall-clock, randomness, or OS dependencies. Inject time deterministically via `MonoTime`.
4. **Modular files:** Keep every `.rs` source file `<= 350` lines (target `<= 250-300` lines). Split modules cleanly by responsibility.
5. **Zero personal configurations or private data:** Never embed personal hostnames, user home paths, private IPs, GCP project IDs, SSH/age keys, or OAuth credentials. Use RFC 3849/4193 IPv6 documentation ranges (`2001:db8::/32`, `fd00:db8::/64`, `[::1]:0`).
6. **Self-contained platform:** Hephaestus must never depend on external sibling platform repositories (`Nomos`, `FabricO11y`, `Metron`, `Jacquard`).
7. **SHA-pinned workflows:** Every `uses:` in `.github/workflows/*.yml` must pin a full 40-character commit SHA (`cargo xtask check-workflow-pins`).
