#![forbid(unsafe_code)]
//! Authoritative SQLite WAL (`page_size = 16384`) catalog, idempotency ledger,
//! MMR-backed Decision & Observation Log persistence, and `"LTX1"` snapshot adapter.

mod catalog;
mod decision_logs;
mod ltx;
mod mmr_store;
mod observation_logs;
mod schema;
mod store;

pub use ltx::{LTX_SNAPSHOT_MAGIC, restore_ltx_snapshot_zstd};
pub use store::SqliteStore;
