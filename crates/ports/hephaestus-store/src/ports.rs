//! Driven port traits separating domain logic from SQLite, object backends, and webhooks.

use crate::types::{
    BlobLocation, BoxFuture, CatalogStats, CommitRef, IdempotentReceipt, ObjectMeta, ObjectRef,
    PushWebhookEvent, StoreError,
};
use bytes::Bytes;
use core::ops::Range;
use hephaestus_core::{
    BlobDigest, ChangeId, DecisionDraft, DecisionRecord, IdempotencyKey, ObservationDraft,
    ObservationFilter, ObservationRecord, RepoId, SealedBundle,
};

/// Object storage port for immutable `GRNB0002` bundles and snapshots.
pub trait ObjectBackend: Send + Sync {
    /// Stable backend identifier (e.g., `"localfs"`, `"s3"`, `"gcs"`, `"google-drive"`, `"memory"`).
    fn backend_kind(&self) -> &'static str;

    /// Uploads a compressed bundle or snapshot under `bundle_key` and returns its [`ObjectRef`].
    fn put_bundle<'a>(
        &'a self,
        bundle_key: &'a str,
        bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<ObjectRef, StoreError>>;

    /// Downloads the compressed object identified by `object_id`.
    fn get_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StoreError>>;

    /// Downloads a half-open byte range `[range.start..range.end)` from `object_id`.
    fn get_range<'a>(
        &'a self,
        object_id: &'a str,
        range: Range<u64>,
    ) -> BoxFuture<'a, Result<Bytes, StoreError>>;

    /// Checks existence and byte length of `object_id` without downloading its payload.
    fn head_bundle<'a>(
        &'a self,
        object_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<ObjectMeta>, StoreError>>;

    /// Deletes an object by `object_id` (primarily for retention/GC).
    fn delete_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<(), StoreError>>;
}

/// Authoritative SQLite WAL catalog, idempotency ledger, and LTX snapshot port.
pub trait CatalogStore: Send + Sync {
    /// Stores a small (`<= 8 KiB`) blob inline in the catalog.
    fn put_inline<'a>(
        &'a self,
        digest: &'a BlobDigest,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Returns `true` if `digest` exists inline or in a recorded bundle.
    fn contains_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<bool, StoreError>>;

    /// Looks up inline payload bytes or packed bundle coordinates for `digest`.
    fn lookup_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<Option<BlobLocation>, StoreError>>;

    /// Atomically persists a flushed bundle and all packed blob index rows.
    fn record_bundle<'a>(
        &'a self,
        bundle: &'a SealedBundle,
        object_id: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Checks whether `key` was already durably committed, returning its cached ack payload.
    fn check_idempotent<'a>(
        &'a self,
        key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>>;

    /// Atomically checks and records `(repo_id, stream_kind, blake3_digest)` with `ack_payload`.
    fn record_idempotent<'a>(
        &'a self,
        key: &'a IdempotencyKey,
        ack_payload: &'a [u8],
        now_ms: u64,
    ) -> BoxFuture<'a, Result<IdempotentReceipt, StoreError>>;

    /// Upserts an authoritative bookmark/ref state for a repository.
    fn upsert_ref<'a>(&'a self, commit_ref: &'a CommitRef)
    -> BoxFuture<'a, Result<(), StoreError>>;

    /// Lists all bookmarks/refs recorded for `repo_id`.
    fn list_refs<'a>(
        &'a self,
        repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<Vec<CommitRef>, StoreError>>;

    /// Returns aggregate catalog and log row counts.
    fn stats(&self) -> BoxFuture<'_, Result<CatalogStats, StoreError>>;

    /// Performs a passive SQLite WAL checkpoint.
    fn checkpoint_wal(&self) -> BoxFuture<'_, Result<(), StoreError>>;

    /// Exports a consistent Zstd-compressed LTX snapshot of the live database.
    fn export_ltx_snapshot_zstd(&self) -> BoxFuture<'_, Result<Vec<u8>, StoreError>>;
}

/// Append-only port for hash-chained Decision Logs and orthogonal Observation Logs.
pub trait LogStore: Send + Sync {
    /// Appends a hash-chained Decision Log entry for `repo_id`.
    fn append_decision<'a>(
        &'a self,
        repo_id: &'a RepoId,
        draft: DecisionDraft,
    ) -> BoxFuture<'a, Result<DecisionRecord, StoreError>>;

    /// Lists Decision Log records for `repo_id`, optionally filtered by `change_id`.
    fn list_decisions<'a>(
        &'a self,
        repo_id: &'a RepoId,
        change_id: Option<&'a ChangeId>,
    ) -> BoxFuture<'a, Result<Vec<DecisionRecord>, StoreError>>;

    /// Verifies the full cryptographic Decision Log chain for `repo_id`.
    fn verify_decisions<'a>(
        &'a self,
        repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<u64, StoreError>>;

    /// Appends an orthogonal Observation Log entry for `repo_id`.
    fn append_observation<'a>(
        &'a self,
        repo_id: &'a RepoId,
        draft: ObservationDraft,
    ) -> BoxFuture<'a, Result<ObservationRecord, StoreError>>;

    /// Queries Observation Log records matching `filter` within `repo_id`.
    fn query_observations<'a>(
        &'a self,
        repo_id: &'a RepoId,
        filter: &'a ObservationFilter,
    ) -> BoxFuture<'a, Result<Vec<ObservationRecord>, StoreError>>;

    /// Verifies the full cryptographic Observation Log chain for `repo_id`.
    fn verify_observations<'a>(
        &'a self,
        repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<u64, StoreError>>;
}

/// Outbound push notification port for CI runners and control planes.
pub trait WebhookSink: Send + Sync {
    /// Emits a push notification, returning `true` when acknowledged by the downstream sink.
    fn notify_push<'a>(
        &'a self,
        event: &'a PushWebhookEvent,
    ) -> BoxFuture<'a, Result<bool, StoreError>>;
}
