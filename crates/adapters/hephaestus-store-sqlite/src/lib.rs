#![forbid(unsafe_code)]
//! Authoritative SQLite WAL (`page_size = 16384`) catalog, idempotency ledger,
//! MMR-backed Decision & Observation Log persistence, and `"LTX1"` snapshot adapter.

mod catalog;
mod decision_logs;
mod log_rows;
mod ltx;
mod mmr_store;
mod observation_logs;
mod schema;
mod store;
mod store_traits;

pub use ltx::{
    LTX_SNAPSHOT_MAGIC, MAX_LTX_COMPRESSED_BYTES, MAX_LTX_DECOMPRESSED_BYTES,
    restore_ltx_snapshot_zstd, restore_ltx_snapshot_zstd_verified,
};
pub use store::SqliteStore;
