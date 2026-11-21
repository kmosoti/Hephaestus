//! Shared error, future, and metadata types across Hephaestus storage ports.

use core::future::Future;
use core::pin::Pin;
use hephaestus_core::{
    BlobDigest, BundleError, ChainError, ChangeId, CommitId, IdError, OpId, RepoId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Object-safe boxed future alias used across async port traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Unified error type returned by driven storage, catalog, log, and webhook adapters.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Requested object, blob, or repository resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// Caller supplied an invalid identifier, digest, or filter.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Conflicting state or concurrent sequence violation.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Hash-chain integrity invariant failed.
    #[error("chain integrity violation: {0}")]
    ChainViolation(#[from] ChainError),

    /// Identifier validation failed.
    #[error("identifier error: {0}")]
    Id(#[from] IdError),

    /// Bundle packing/unpacking error.
    #[error("bundle error: {0}")]
    Bundle(#[from] BundleError),

    /// Remote backend rejected request due to rate limiting.
    #[error("rate limited by backend: {0}")]
    RateLimited(String),

    /// Serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Underlying I/O or backend storage failure.
    #[error("backend error: {0}")]
    Backend(String),
}

/// Reference returned after uploading a bundle object to an [`crate::ObjectBackend`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Backend-specific immutable object key or Google Drive `fileId`.
    pub object_id: String,
    /// Compressed object byte size.
    pub size_bytes: u64,
    /// Optional content ETag or digest reported by backend.
    pub etag: Option<String>,
}

/// Lightweight metadata returned by [`crate::ObjectBackend::head_bundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// Object key or `fileId`.
    pub object_id: String,
    /// Size in bytes.
    pub size_bytes: u64,
}

/// Resolved storage location for a content-addressed blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobLocation {
    /// Stored inline inside SQLite WAL (`<= 8 KiB`).
    Inline(Vec<u8>),
    /// Packed inside a `GRNB0002` bundle on the [`crate::ObjectBackend`].
    Packed {
        /// Object key or Drive `fileId`.
        object_id: String,
        /// Bundle identifier.
        bundle_id: String,
        /// Byte offset inside the bundle's uncompressed payload space.
        byte_offset: u64,
        /// Uncompressed byte length of this blob.
        byte_len: u32,
    },
}

/// Aggregate repository catalog and log counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogStats {
    /// Blobs stored inline in SQLite.
    pub inline_count: u64,
    /// Blobs packed into bundles.
    pub packed_count: u64,
    /// Sealed bundles recorded.
    pub bundle_count: u64,
    /// Idempotency ledger entries recorded.
    pub idempotency_count: u64,
    /// Decision Log records across repositories.
    pub decision_count: u64,
    /// Orthogonal Observation Log records across repositories.
    pub observation_count: u64,
}

/// Authoritative bookmark / commit reference tracked for a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRef {
    /// Repository identifier.
    pub repo_id: RepoId,
    /// Bookmark or ref name (e.g., `main`, `stack/alpha/01`).
    pub bookmark: String,
    /// Jujutsu `ChangeId`.
    pub change_id: ChangeId,
    /// Jujutsu `CommitId`.
    pub commit_id: CommitId,
    /// Jujutsu `OpId` that produced or observed this ref update.
    pub op_id: OpId,
    /// Hex-encoded BLAKE3 digest of the serialized tree manifest blob.
    pub tree_blob_hash: String,
    /// Timestamp in milliseconds.
    pub updated_ms: u64,
}

/// Outcome of checking/recording an atomic idempotency entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotentReceipt {
    /// `true` when `(repo_id, stream_kind, blake3_digest)` was already committed.
    pub already_applied: bool,
    /// Canonical acknowledgment payload bytes stored with the entry.
    pub ack_payload: Vec<u8>,
}

/// Webhook payload delivered after a push or Jujutsu operation is durably committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushWebhookEvent {
    /// Repository identifier.
    pub repo_id: RepoId,
    /// Updated bookmark name.
    pub bookmark: String,
    /// Jujutsu `ChangeId`.
    pub change_id: ChangeId,
    /// Jujutsu `CommitId`.
    pub commit_id: CommitId,
    /// Jujutsu `OpId`.
    pub op_id: OpId,
    /// Hex-encoded BLAKE3 digest of the tree manifest blob.
    pub tree_blob_hash: String,
}

/// Metadata describing an exported Zstd LTX SQLite snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Snapshot sequence identifier.
    pub snapshot_seq: u64,
    /// SQLite page size in bytes (16,384).
    pub page_size: u32,
    /// Number of SQLite database pages captured.
    pub page_count: u32,
    /// BLAKE3 digest of the uncompressed SQLite snapshot bytes.
    pub raw_digest: BlobDigest,
    /// Compressed LTX payload size in bytes.
    pub compressed_bytes: u64,
}
