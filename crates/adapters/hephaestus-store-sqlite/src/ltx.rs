//! Real Litestream `"LTX1"` SQLite snapshot emission, `ltx_snapshots` tracking,
//! and atomic `fsync`-durable crash-recovery restore.

use crate::schema::{SQLITE_PAGE_SIZE, blob_to_digest, io_err, query_page_size, sqlite_err};
use crate::store::SqliteStore;
use hephaestus_core::{
    BlobDigest, LTX_MAGIC, LtxDocument, decode_ltx, encode_snapshot_ltx, reconstruct_db_from_ltx,
};
use hephaestus_store::{SnapshotMetadata, StoreError};
use rusqlite::{Connection, OptionalExtension, params};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 4-byte Litestream `"LTX1"` wire magic prefix.
pub const LTX_SNAPSHOT_MAGIC: &[u8; 4] = LTX_MAGIC;
/// Maximum compressed LTX1 snapshot payload accepted for restore (`256 MiB`).
pub const MAX_LTX_COMPRESSED_BYTES: usize = 256 * 1024 * 1024;
/// Maximum decompressed LTX1 document size permitted during restore (`256 MiB`).
pub const MAX_LTX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;
const MAX_LTX_PAGE_COUNT: u32 = (MAX_LTX_DECOMPRESSED_BYTES / (SQLITE_PAGE_SIZE as usize)) as u32;
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
static STAGE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn unique_stage_path(base_dir: Option<&Path>) -> PathBuf {
    let seq = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = base_dir
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(std::env::temp_dir, Path::to_path_buf);
    root.join(format!(
        ".hephaestus-ltx-stage-{}-{seq}.sqlite",
        std::process::id()
    ))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().min(u128::from(i64::MAX as u64)) as i64)
}

/// Exports a consistent `"LTX1"` page-frame snapshot compressed with Zstd, and records its
/// metadata row in `ltx_snapshots`.
pub(crate) fn export_ltx_snapshot_zstd_sync(
    conn: &Connection,
    db_dir: Option<&Path>,
) -> Result<Vec<u8>, StoreError> {
    let page_size = query_page_size(conn)?;
    let stage = unique_stage_path(db_dir);
    if let Some(parent) = stage.parent() {
        std::fs::create_dir_all(parent).map_err(io_err)?;
    }

    let backup_res = (|| -> Result<Vec<u8>, StoreError> {
        let mut dst = Connection::open(&stage).map_err(sqlite_err)?;
        {
            let backup = rusqlite::backup::Backup::new(conn, &mut dst).map_err(sqlite_err)?;
            backup
                .run_to_completion(64, Duration::from_millis(1), None)
                .map_err(sqlite_err)?;
        }
        drop(dst);
        std::fs::read(&stage).map_err(io_err)
    })();
    let _ = std::fs::remove_file(&stage);
    let raw = backup_res?;

    let prev_seq: Option<i64> = conn
        .query_row("SELECT MAX(snapshot_seq) FROM ltx_snapshots", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(sqlite_err)?
        .flatten();
    let next_txid = prev_seq.map_or(1u64, |s| (s.max(0) as u64).saturating_add(1));
    let created_ms = now_unix_ms();

    let (ltx_bytes, hdr, _trailer) = encode_snapshot_ltx(&raw, page_size, next_txid, created_ms)
        .map_err(|e| StoreError::Backend(format!("encode LTX1: {e}")))?;
    let digest = BlobDigest::of(&raw);
    let compressed = zstd::bulk::compress(&ltx_bytes, 3)
        .map_err(|e| StoreError::Backend(format!("zstd compress LTX1: {e}")))?;

    conn.execute(
        "INSERT INTO ltx_snapshots
         (page_size, page_count, raw_digest, compressed_bytes, created_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            i64::from(hdr.page_size),
            i64::from(hdr.commit),
            digest.as_bytes().as_slice(),
            compressed.len() as i64,
            created_ms,
        ],
    )
    .map_err(sqlite_err)?;
    Ok(compressed)
}

/// Counts recorded snapshots in `ltx_snapshots`.
pub(crate) fn ltx_snapshot_count_sync(conn: &Connection) -> Result<u64, StoreError> {
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM ltx_snapshots", [], |r| r.get(0))
        .map_err(sqlite_err)?;
    Ok(n as u64)
}

/// Returns the latest recorded snapshot metadata from `ltx_snapshots`, if any.
pub(crate) fn latest_ltx_snapshot_meta_sync(
    conn: &Connection,
) -> Result<Option<SnapshotMetadata>, StoreError> {
    let row: Option<(i64, i64, i64, Vec<u8>, i64)> = conn
        .query_row(
            "SELECT snapshot_seq, page_size, page_count, raw_digest, compressed_bytes
             FROM ltx_snapshots ORDER BY snapshot_seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .map_err(sqlite_err)?;
    let Some((seq, ps, pc, raw_dig, comp_len)) = row else {
        return Ok(None);
    };
    Ok(Some(SnapshotMetadata {
        snapshot_seq: seq.max(0) as u64,
        page_size: ps.max(0) as u32,
        page_count: pc.max(0) as u32,
        raw_digest: blob_to_digest(&raw_dig, "ltx_snapshots.raw_digest")?,
        compressed_bytes: comp_len.max(0) as u64,
    }))
}

fn ct_eq_digest(a: &BlobDigest, b: &BlobDigest) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a.0[i] ^ b.0[i];
    }
    std::hint::black_box(diff) == 0
}

fn decode_and_reconstruct_ltx(snapshot: &[u8]) -> Result<(LtxDocument, Vec<u8>), StoreError> {
    if snapshot.len() > MAX_LTX_COMPRESSED_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "LTX1 compressed snapshot exceeds maximum size of {MAX_LTX_COMPRESSED_BYTES} bytes"
        )));
    }
    let ltx_bytes = if snapshot.starts_with(&ZSTD_MAGIC) {
        let dec = zstd::stream::Decoder::new(snapshot)
            .map_err(|e| StoreError::InvalidInput(format!("LTX1 zstd init failed: {e}")))?;
        let mut out = Vec::new();
        dec.take((MAX_LTX_DECOMPRESSED_BYTES as u64) + 1)
            .read_to_end(&mut out)
            .map_err(|e| StoreError::InvalidInput(format!("LTX1 zstd decode failed: {e}")))?;
        if out.len() > MAX_LTX_DECOMPRESSED_BYTES {
            return Err(StoreError::InvalidInput(format!(
                "LTX1 snapshot exceeds maximum decompressed size of {MAX_LTX_DECOMPRESSED_BYTES} bytes"
            )));
        }
        out
    } else if snapshot.starts_with(LTX_MAGIC) {
        if snapshot.len() > MAX_LTX_DECOMPRESSED_BYTES {
            return Err(StoreError::InvalidInput(format!(
                "LTX1 snapshot exceeds maximum size of {MAX_LTX_DECOMPRESSED_BYTES} bytes"
            )));
        }
        snapshot.to_vec()
    } else {
        return Err(StoreError::InvalidInput(
            "corrupt LTX1 snapshot header or magic mismatch".into(),
        ));
    };

    let doc = decode_ltx(&ltx_bytes)
        .map_err(|e| StoreError::InvalidInput(format!("LTX1 decode failed: {e}")))?;
    if doc.header.page_size != SQLITE_PAGE_SIZE {
        return Err(StoreError::InvalidInput(format!(
            "unexpected LTX1 page_size {}, expected {SQLITE_PAGE_SIZE}",
            doc.header.page_size
        )));
    }
    if doc.header.min_txid != 1 {
        return Err(StoreError::InvalidInput(format!(
            "LTX1 full snapshot requires min_txid == 1, got {}",
            doc.header.min_txid
        )));
    }
    if doc.header.commit > MAX_LTX_PAGE_COUNT {
        return Err(StoreError::InvalidInput(format!(
            "LTX1 page count {} exceeds limit {MAX_LTX_PAGE_COUNT}",
            doc.header.commit
        )));
    }
    let raw = reconstruct_db_from_ltx(&doc)
        .map_err(|e| StoreError::InvalidInput(format!("LTX1 reconstruct failed: {e}")))?;
    Ok((doc, raw))
}

fn write_and_open_restored_db(raw: &[u8], dest: &Path) -> Result<SqliteStore, StoreError> {
    let parent_dir = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent_dir).map_err(io_err)?;

    let tmp_path = unique_stage_path(Some(parent_dir));
    {
        let mut f = File::create(&tmp_path).map_err(io_err)?;
        f.write_all(raw).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
    }

    // Remove stale WAL/SHM sidecars before atomic replacement.
    let wal_path = PathBuf::from(format!("{}-wal", dest.display()));
    let shm_path = PathBuf::from(format!("{}-shm", dest.display()));
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(&shm_path);

    std::fs::rename(&tmp_path, dest).map_err(io_err)?;
    if let Ok(dir_handle) = File::open(parent_dir) {
        let _ = dir_handle.sync_all();
    }
    SqliteStore::open(dest)
}

/// Verifies bounded Zstd + `"LTX1"` header, page frames, CRC-64/ISO file checksum, and
/// `post_apply_checksum`, then restores atomically with file + directory `fsync` before opening
/// [`SqliteStore`].
pub fn restore_ltx_snapshot_zstd(
    snapshot: &[u8],
    dest_path: impl AsRef<Path>,
) -> Result<SqliteStore, StoreError> {
    let (_doc, raw) = decode_and_reconstruct_ltx(snapshot)?;
    write_and_open_restored_db(&raw, dest_path.as_ref())
}

/// Performs bounded Zstd + `"LTX1"` decode/checksum validation AND verifies the reconstructed
/// database BLAKE3 digest against `expected_digest` (constant-time) and monotonic freshness
/// (`max_txid >= min_txid`) before atomically replacing `dest_path`.
pub fn restore_ltx_snapshot_zstd_verified(
    snapshot: &[u8],
    dest_path: impl AsRef<Path>,
    expected_digest: &BlobDigest,
    min_txid: Option<u64>,
) -> Result<SqliteStore, StoreError> {
    let (doc, raw) = decode_and_reconstruct_ltx(snapshot)?;
    if let Some(min) = min_txid
        && doc.header.max_txid < min
    {
        return Err(StoreError::InvalidInput(format!(
            "LTX1 snapshot txid {} is older than required minimum {min}",
            doc.header.max_txid
        )));
    }
    let actual_digest = BlobDigest::of(&raw);
    if !ct_eq_digest(&actual_digest, expected_digest) {
        return Err(StoreError::InvalidInput(
            "LTX1 snapshot BLAKE3 digest mismatch".into(),
        ));
    }
    write_and_open_restored_db(&raw, dest_path.as_ref())
}
