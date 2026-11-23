//! SQLite schema DDL (`page_size = 16384`, WAL mode) and error conversion helpers.

use hephaestus_core::BlobDigest;
use hephaestus_store::StoreError;
use rusqlite::Connection;

/// Configured SQLite page size (16 KiB) aligned with LTX1 snapshots and WAL pages.
pub(crate) const SQLITE_PAGE_SIZE: u32 = 16_384;

pub(crate) fn sqlite_err(err: rusqlite::Error) -> StoreError {
    StoreError::Backend(format!("sqlite error: {err}"))
}

pub(crate) fn io_err(err: std::io::Error) -> StoreError {
    StoreError::Backend(format!("sqlite i/o error: {err}"))
}

pub(crate) fn json_err(err: serde_json::Error) -> StoreError {
    StoreError::Serialization(format!("json error: {err}"))
}

pub(crate) fn init_schema(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "PRAGMA busy_timeout = 5000;
         PRAGMA page_size = 16384;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS inline_blobs (
             blake3_hash BLOB PRIMARY KEY,
             data BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS bundles (
             bundle_id TEXT PRIMARY KEY,
             object_id TEXT NOT NULL,
             compressed_bytes INTEGER NOT NULL,
             entry_count INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS packed_objects (
             blake3_hash BLOB PRIMARY KEY,
             object_id TEXT NOT NULL,
             bundle_id TEXT NOT NULL,
             byte_offset INTEGER NOT NULL,
             byte_len INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS idempotency_ledger (
             repo_id TEXT NOT NULL,
             stream_kind TEXT NOT NULL,
             blake3_digest BLOB NOT NULL,
             ack_payload BLOB NOT NULL,
             created_ms INTEGER NOT NULL,
             PRIMARY KEY (repo_id, stream_kind, blake3_digest)
         );
         CREATE TABLE IF NOT EXISTS refs (
             repo_id TEXT NOT NULL,
             bookmark TEXT NOT NULL,
             change_id TEXT NOT NULL,
             commit_id TEXT NOT NULL,
             op_id TEXT NOT NULL,
             tree_blob_hash TEXT NOT NULL,
             updated_ms INTEGER NOT NULL,
             PRIMARY KEY (repo_id, bookmark)
         );
         CREATE TABLE IF NOT EXISTS decisions (
             repo_id TEXT NOT NULL,
             seq INTEGER NOT NULL,
             decision_id TEXT NOT NULL,
             prev_hash BLOB NOT NULL,
             record_hash BLOB NOT NULL,
             mmr_root BLOB NOT NULL,
             change_id TEXT NOT NULL,
             op_id TEXT NOT NULL,
             author TEXT NOT NULL,
             status TEXT NOT NULL,
             rationale TEXT NOT NULL,
             alternatives_json TEXT NOT NULL,
             supersedes TEXT,
             recorded_at_ms INTEGER NOT NULL,
             PRIMARY KEY (repo_id, seq),
             UNIQUE (repo_id, decision_id)
         );
         CREATE INDEX IF NOT EXISTS idx_decisions_change
             ON decisions (repo_id, change_id, seq);
         CREATE TABLE IF NOT EXISTS observations (
             repo_id TEXT NOT NULL,
             seq INTEGER NOT NULL,
             observation_id TEXT NOT NULL,
             prev_hash BLOB NOT NULL,
             record_hash BLOB NOT NULL,
             mmr_root BLOB NOT NULL,
             kind TEXT NOT NULL,
             change_id TEXT NOT NULL,
             commit_id TEXT NOT NULL,
             op_id TEXT NOT NULL,
             producer TEXT NOT NULL,
             passed INTEGER,
             summary TEXT NOT NULL,
             payload_digest BLOB NOT NULL,
             custody_uri TEXT,
             metadata_json TEXT NOT NULL,
             recorded_at_ms INTEGER NOT NULL,
             PRIMARY KEY (repo_id, seq),
             UNIQUE (repo_id, observation_id)
         );
         CREATE INDEX IF NOT EXISTS idx_observations_change
             ON observations (repo_id, change_id, seq);
         CREATE INDEX IF NOT EXISTS idx_observations_commit
             ON observations (repo_id, commit_id, seq);
         CREATE INDEX IF NOT EXISTS idx_observations_kind
             ON observations (repo_id, kind, seq);
         CREATE TABLE IF NOT EXISTS mmr_nodes (
             repo_id TEXT NOT NULL,
             stream_kind TEXT NOT NULL,
             pos INTEGER NOT NULL,
             node_hash BLOB NOT NULL,
             PRIMARY KEY (repo_id, stream_kind, pos)
         );
         CREATE TABLE IF NOT EXISTS ltx_snapshots (
             snapshot_seq INTEGER PRIMARY KEY AUTOINCREMENT,
             page_size INTEGER NOT NULL,
             page_count INTEGER NOT NULL,
             raw_digest BLOB NOT NULL,
             compressed_bytes INTEGER NOT NULL,
             created_ms INTEGER NOT NULL
         );",
    )
    .map_err(sqlite_err)
}

pub(crate) fn query_page_size(conn: &Connection) -> Result<u32, StoreError> {
    conn.pragma_query_value(None, "page_size", |r| r.get(0))
        .map_err(sqlite_err)
}

pub(crate) fn blob_to_digest(bytes: &[u8], field: &str) -> Result<BlobDigest, StoreError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::Backend(format!("corrupt 32-byte digest in `{field}`")))?;
    Ok(BlobDigest(arr))
}
