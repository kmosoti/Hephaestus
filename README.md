# Hephaestus

**Hephaestus** is an authoritative Jujutsu (`jj-lib 0.47`) storage backend powered by native FastCDC + BLAKE3 CAS, bounded range-read `GRNB0002` Zstd bundling, Bao verified streaming, BLAKE3 MMR + JCS hash-chained Decision & Orthogonal Observation Logs, real Litestream `"LTX1"` SQLite WAL snapshots, and a pure-IPv6 Ed25519 mTLS SPKI-pinned QUIC + streaming Git smart-HTTP server.

- **License:** Apache-2.0 ([LICENSE](LICENSE))
- **Toolchain:** Rust `1.100.0` (Edition 2024, `resolver = "3"`)
- **Safety:** `#![forbid(unsafe_code)]`, `#![no_std]` Sans-I/O core, zero Python anywhere

## Quickstart 1: Zero-Cloud Local Server

Run Hephaestus locally with zero cloud credentials (`SqliteStore` WAL + `LocalFs` object storage over IPv6 loopback). For production, supply `--http-auth-token-file` (`0600`/`0400` regular file, verified in constant time via SHA-256), one or more `--allow-client-fp <64-hex-spki-sha256>` pins, and `--tls-key-path` (or systemd `LoadCredentialEncrypted=tls-ed25519.pem`); pass `--dev-ephemeral` and `--allow-unauthenticated-loopback-http` only for local development:

```sh
cargo run --locked -p hephaestus-server -- \
  --http-bind [::1]:8081 \
  --quic-bind [::1]:8443 \
  --data-dir ./hephaestus-data \
  --allow-unauthenticated-loopback-http \
  --dev-ephemeral
```

Wait for `http=[::1]:8081 quic=[::1]:8443 quic_fp=<64-hex>`, then query the IPv6 HTTP/1.1 bridge:

```sh
# Health & stats
curl -sS -g 'http://[::1]:8081/health' | jq .
curl -sS -g 'http://[::1]:8081/v1/stats' | jq .

# Store a blob idempotently (repeating returns deduplicated: true)
curl -sS -g -X POST 'http://[::1]:8081/v1/blobs?repo=example/repo' \
  --data-binary 'hello hephaestus' | jq .

# Flush staged GRNB0002 Zstd bundles to the object backend
curl -sS -g -X POST 'http://[::1]:8081/v1/flush' | jq .
```

Run the standalone IPv6 QUIC + HTTP workload benchmark:

```sh
cargo run --locked -p hephaestus-server --example vcs_workload
```

## Quickstart 2: S3 / Cloudflare R2 / GCS (`object_store`)

Select any `object_store` (`0.14.x`) URI via `--object-uri` (`file:///path`, `memory://`, `s3://bucket/prefix`, `gs://bucket/prefix`) — `PackedCasEngine` uses bounded `ObjectBackend::get_range` reads to fetch only the `GRNB0002` frame directory + target Zstd frame:

```sh
hephaestus-server \
  --http-bind '[::1]:8081' \
  --quic-bind '[::1]:8443' \
  --data-dir /var/lib/hephaestus \
  --http-auth-token-file /run/secrets/hephaestus-http-token \
  --object-uri 's3://my-hephaestus-cas/prod' \
  --allow-client-fp '<64-hex-spki-sha256>'
```

## Quickstart 3: Google Drive (`drive.file`, 20 TB)

Enable the hardened native-IPv6 `GoogleDriveStore` (`DriveOAuthFsm` refresh, 8 MiB 256 KiB-aligned `Content-Range` `308` resumable uploads, HTTP `Range:` reads, `Retry-After` + `403` rate-limit classification, and paginated `list_bundles` DR recovery) via `--drive-url` and `CREDENTIALS_DIRECTORY/drive-access-token`:

```sh
# Pass empty string "" to use https://www.googleapis.com/drive/v3
hephaestus-server \
  --http-bind '[::1]:8081' \
  --quic-bind '[::1]:8443' \
  --data-dir /var/lib/hephaestus \
  --http-auth-token-file /run/secrets/hephaestus-http-token \
  --drive-url '' \
  --allow-client-fp '<64-hex-spki-sha256>'
```

## Decision Log, Observation Logs, MMR Proofs, & `"LTX1"` Snapshots

Hephaestus maintains two hash-chained + BLAKE3 MMR-committed append-only audit streams keyed by Jujutsu `(ChangeId, CommitId, OpId)`, with RFC 8785 (JCS) canonicalized `metadata_json` hashing, parameterized SQL predicate pushdown (`change_id`, `commit_id`, `op_id`, `kind`, `passed`, `since_seq`, `limit`), and `O(log N)` MMR inclusion proofs persisted in SQLite `mmr_nodes`.

Background Litestream `"LTX1"` Zstd snapshots (`--ltx-interval-secs`, default `300`) ship 16 KiB SQLite page frames with CRC-64/ISO file & `post_apply_checksum` verification to `ObjectBackend` and record metadata in `ltx_snapshots`.

```sh
# Query filtered observations with SQL predicate pushdown and pagination
curl -sS -g 'http://[::1]:8081/v1/observations/example%2Frepo?kind=verifier_verdict&passed=true&since_seq=0&limit=50' | jq .
curl -sS -g 'http://[::1]:8081/v1/observations/example%2Frepo/verify' | jq .
curl -sS -g 'http://[::1]:8081/v1/decisions/example%2Frepo/verify' | jq .
```

Programmatic QUIC clients connect with `HephaestusQuicClient::connect(quic_addr, &client_identity, server_spki_pin)` over pure IPv6 with chunked streaming up to 16 MiB and a weighted 64 MiB aggregate inflight byte budget.

## Native Jujutsu CAS Backend & Streaming Git Smart-HTTP Bridge

- **`HephaestusBackend` (`hephaestus-jj`)**: Native `jj-lib` storage backend using FastCDC (`8/32/128 KiB`) chunking and BLAKE3 CAS manifests for files alongside content-addressed trees, commits, and symlinks.
- **Multi-Repo Streaming Git Smart-HTTP**: Pass `--jj-repo /path/to/repos` to serve `/git/{repo}/info/refs`, `/git/{repo}/git-upload-pack`, and `/git/{repo}/git-receive-pack` (`{repo}` validated against `^[a-zA-Z0-9._-]+$`). Packfiles stream through async `git` child pipes without RAM buffering; successful `git-receive-pack` pushes import refs into `jj` OpLog, sync blobs to CAS, and fire `WebhookSink`.

## NixOS Module (`services.hephaestus`)

Import `nixosModules.hephaestus` from [flake.nix](flake.nix) (see [nix/modules/hephaestus.nix](nix/modules/hephaestus.nix)):

```nix
{
  imports = [ hephaestus.nixosModules.hephaestus ];

  services.hephaestus = {
    enable = true;
    httpListenAddress = "[fd00:db8::1]:8081";
    quicListenAddress = "[fd00:db8::1]:8443";
    httpAuthTokenFile = "/run/secrets/hephaestus-http-token";
    tlsKeyEncryptedFile = /etc/credstore.encrypted/hephaestus-tls-ed25519.cred;
    ltxIntervalSecs = 300;
    allowClientFingerprints = [
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ];
    openFirewall = true;
  };
}
```

## Packaging & Verification Gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo xtask check-layers
cargo xtask check-core-purity
cargo xtask check-workflow-pins
cargo xtask package-deb --out dist
```

Release artifacts written under `dist/` include `hephaestus-server_<version>_amd64.deb`, `hephaestus-server-<version>-x86_64-linux.tar.zst`, and `SHA256SUMS`. Tagging `v*` triggers [.github/workflows/release.yml](.github/workflows/release.yml) with `RELEASE-EVIDENCE.json` and `actions/attest-build-provenance`.

## Contributing

See [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/adr/0000-foundations.md](docs/adr/0000-foundations.md).
