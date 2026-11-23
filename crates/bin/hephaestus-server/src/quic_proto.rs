//! Wire message types and framing bounds for multiplexed QUIC streams across blobs,
//! `jj` ops, Decision Log, and Observation Logs.

use hephaestus_core::{
    ChangeId, DecisionDraft, DecisionRecord, ObservationDraft, ObservationFilter,
    ObservationRecord, RepoId,
};
use hephaestus_jj::JjOpSummary;
use hephaestus_store::{CatalogStats, CommitRef};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Maximum JSON header size per QUIC stream (1 MiB).
pub const MAX_QUIC_HEADER_BYTES: usize = 1024 * 1024;
/// Maximum streamed binary payload size per QUIC stream (16 MiB).
pub const MAX_QUIC_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Streaming chunk size written/read per QUIC stream step (64 KiB).
pub const QUIC_STREAM_CHUNK_BYTES: usize = 64 * 1024;
/// Default absolute deadline for reading a single QUIC stream message.
pub const DEFAULT_QUIC_STREAM_DEADLINE: Duration = Duration::from_secs(60);

/// Operation discriminant carried on each bidirectional QUIC stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicStreamOp {
    /// Health and backend summary check.
    Health,
    /// Idempotent CAS blob upload (`<= 8 KiB` inline or `> 8 KiB` packed).
    PutBlob,
    /// Content-addressed blob retrieval by BLAKE3 hex digest.
    GetBlob,
    /// Seal staged `GRNB0002` bundle and upload to object backend.
    FlushBundle,
    /// Idempotent bookmark / `jj` commit ref replication.
    PushRef,
    /// List replicated bookmarks for a repository.
    ListRefs,
    /// Idempotent append to the hash-chained Decision Log.
    AppendDecision,
    /// Query Decision Log entries by repository and optional `ChangeId`.
    QueryDecisions,
    /// Verify cryptographic integrity of the Decision Log chain.
    VerifyDecisions,
    /// Idempotent append to the orthogonal Observation Log.
    AppendObservation,
    /// Query orthogonal Observation Log entries with typed filter.
    QueryObservations,
    /// Verify cryptographic integrity of the Observation Log chain.
    VerifyObservations,
    /// List Jujutsu OpLog summaries from the configured repository.
    JjListOps,
}

/// Multiplexed request envelope sent over a `quinn` bidirectional stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum QuicRequest {
    /// Health + catalog stats query.
    Health,
    /// Store a blob with idempotent `(repo_id, "blob", blake3)` key.
    PutBlob {
        /// Repository scope for idempotency tracking.
        repo_id: RepoId,
        /// Force packing into `GRNB0002` regardless of inline threshold.
        force_pack: bool,
        /// Raw blob payload bytes (streamed binary section on wire).
        #[serde(skip)]
        payload: Vec<u8>,
    },
    /// Retrieve a blob by BLAKE3 hex digest.
    GetBlob {
        /// 64-character BLAKE3 hex digest.
        digest_hex: String,
    },
    /// Seal and flush staged `GRNB0002` blobs.
    FlushBundle,
    /// Replicate a commit/bookmark update idempotently.
    PushRef {
        /// Authoritative commit reference.
        commit_ref: CommitRef,
    },
    /// List bookmark refs for `repo_id`.
    ListRefs {
        /// Repository identifier.
        repo_id: RepoId,
    },
    /// Append a hash-chained decision record idempotently.
    AppendDecision {
        /// Repository identifier.
        repo_id: RepoId,
        /// Unchained decision input.
        draft: DecisionDraft,
    },
    /// Query decision records for `repo_id` (optionally filtered and paginated).
    QueryDecisions {
        /// Repository identifier.
        repo_id: RepoId,
        /// Optional `ChangeId` filter.
        change_id: Option<ChangeId>,
        /// Minimum inclusive sequence number (`seq >= since_seq`).
        #[serde(default)]
        since_seq: Option<u64>,
        /// Maximum records to return (capped at `MAX_LOG_PAGE_LIMIT`).
        #[serde(default)]
        limit: Option<usize>,
    },
    /// Verify the full hash chain of `repo_id`'s Decision Log.
    VerifyDecisions {
        /// Repository identifier.
        repo_id: RepoId,
    },
    /// Append an orthogonal observation record idempotently.
    AppendObservation {
        /// Repository identifier.
        repo_id: RepoId,
        /// Unchained observation input.
        draft: ObservationDraft,
    },
    /// Query orthogonal observation records for `repo_id`.
    QueryObservations {
        /// Repository identifier.
        repo_id: RepoId,
        /// Filter criteria across `(ChangeId, CommitId, OpId, kind, passed, since_seq, limit)`.
        filter: ObservationFilter,
    },
    /// Verify the full hash chain of `repo_id`'s Observation Log.
    VerifyObservations {
        /// Repository identifier.
        repo_id: RepoId,
    },
    /// List recent `jj` OpLog entries.
    JjListOps {
        /// Maximum entries to return.
        limit: usize,
    },
}

/// Response returned over a `quinn` bidirectional stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QuicResponse {
    /// Health + catalog stats response.
    Health {
        /// Object backend kind.
        backend: String,
        /// Catalog stats.
        stats: CatalogStats,
        /// Unflushed staged bytes.
        pending_bytes: usize,
    },
    /// Blob stored response.
    BlobPut {
        /// 64-character BLAKE3 hex digest.
        digest_hex: String,
        /// Raw byte length.
        bytes: usize,
        /// `true` if `(repo_id, "blob", digest)` was already committed.
        deduplicated: bool,
    },
    /// Blob fetch response (`payload` streamed in binary section).
    BlobGet {
        /// `true` when found.
        found: bool,
        /// Raw blob bytes.
        #[serde(skip)]
        payload: Vec<u8>,
    },
    /// Bundle flush response.
    Flushed {
        /// Object ID or Drive `fileId` if a bundle was sealed.
        object_id: Option<String>,
    },
    /// Ref replication acknowledgment.
    RefPushed {
        /// Accepted status.
        accepted: bool,
        /// Whether push webhook succeeded.
        webhook_notified: bool,
        /// `true` when replayed idempotently.
        deduplicated: bool,
    },
    /// Listed bookmark refs.
    Refs {
        /// Repository bookmark refs.
        refs: Vec<CommitRef>,
    },
    /// Appended Decision Log record.
    DecisionAppended {
        /// Hash-chained decision record.
        record: DecisionRecord,
        /// `true` when replayed idempotently.
        deduplicated: bool,
    },
    /// Queried Decision Log records.
    Decisions {
        /// Matching decision records.
        records: Vec<DecisionRecord>,
    },
    /// Appended Observation Log record.
    ObservationAppended {
        /// Hash-chained observation record.
        record: ObservationRecord,
        /// `true` when replayed idempotently.
        deduplicated: bool,
    },
    /// Queried Observation Log records.
    Observations {
        /// Matching observation records.
        records: Vec<ObservationRecord>,
    },
    /// Chain verification count response.
    Verified {
        /// Total verified records in chain.
        verified_count: u64,
    },
    /// Listed `jj` OpLog summaries.
    JjOps {
        /// Recent operations.
        ops: Vec<JjOpSummary>,
    },
    /// Application-level error response.
    Error {
        /// Sanitized error message with reference identifier.
        message: String,
    },
}
