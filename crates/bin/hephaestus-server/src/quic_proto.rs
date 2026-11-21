//! Chunked streaming wire framing for multiplexed QUIC streams across blobs, `jj` ops,
//! Decision Log, and Observation Logs.

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
/// Maximum streamed binary payload size per QUIC stream (64 MiB, exceeding 32 MiB bundles).
pub const MAX_QUIC_FRAME_BYTES: usize = 64 * 1024 * 1024;
/// Streaming chunk size written/read per QUIC stream step (64 KiB).
pub const QUIC_STREAM_CHUNK_BYTES: usize = 64 * 1024;

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
    /// Query decision records for `repo_id` (optionally filtered by `change_id`).
    QueryDecisions {
        /// Repository identifier.
        repo_id: RepoId,
        /// Optional `ChangeId` filter.
        change_id: Option<ChangeId>,
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
        /// Human-readable error message.
        message: String,
    },
}

/// Streams `[u32 header_len][header_json][u64 payload_len][chunked payload]` over a QUIC stream.
pub async fn write_stream_message<T: Serialize>(
    send: &mut quinn::SendStream,
    header: &T,
    payload: &[u8],
) -> Result<(), String> {
    let json_bytes = serde_json::to_vec(header).map_err(|e| format!("encode json: {e}"))?;
    if json_bytes.len() > MAX_QUIC_HEADER_BYTES {
        return Err(format!("QUIC header exceeds {MAX_QUIC_HEADER_BYTES} bytes"));
    }
    if payload.len() > MAX_QUIC_FRAME_BYTES {
        return Err(format!("QUIC payload exceeds {MAX_QUIC_FRAME_BYTES} bytes"));
    }
    send.write_all(&(json_bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|e| format!("quic write hdr_len: {e}"))?;
    send.write_all(&json_bytes)
        .await
        .map_err(|e| format!("quic write hdr: {e}"))?;
    send.write_all(&(payload.len() as u64).to_be_bytes())
        .await
        .map_err(|e| format!("quic write payload_len: {e}"))?;
    for chunk in payload.chunks(QUIC_STREAM_CHUNK_BYTES) {
        send.write_all(chunk)
            .await
            .map_err(|e| format!("quic write chunk: {e}"))?;
    }
    send.finish().map_err(|e| format!("quic finish: {e}"))
}

async fn read_exact_timed(
    recv: &mut quinn::RecvStream,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<(), String> {
    tokio::time::timeout(timeout, recv.read_exact(buf))
        .await
        .map_err(|_| "quic stream read timed out".to_owned())?
        .map_err(|e| format!("quic read_exact: {e}"))
}

/// Reads `[u32 header_len][header_json][u64 payload_len][chunked payload]` with per-chunk timeouts.
pub async fn read_stream_message<T: for<'de> Deserialize<'de>>(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
) -> Result<(T, Vec<u8>), String> {
    let mut len_buf = [0u8; 4];
    read_exact_timed(recv, &mut len_buf, read_timeout).await?;
    let hdr_len = u32::from_be_bytes(len_buf) as usize;
    if hdr_len == 0 || hdr_len > MAX_QUIC_HEADER_BYTES {
        return Err(format!("invalid QUIC header length {hdr_len}"));
    }
    let mut hdr_buf = vec![0u8; hdr_len];
    read_exact_timed(recv, &mut hdr_buf, read_timeout).await?;
    let header: T =
        serde_json::from_slice(&hdr_buf).map_err(|e| format!("decode QUIC json: {e}"))?;

    let mut pay_len_buf = [0u8; 8];
    read_exact_timed(recv, &mut pay_len_buf, read_timeout).await?;
    let payload_len = usize::try_from(u64::from_be_bytes(pay_len_buf))
        .map_err(|_| "QUIC payload length overflow".to_owned())?;
    if payload_len > MAX_QUIC_FRAME_BYTES {
        return Err(format!("QUIC payload exceeds {MAX_QUIC_FRAME_BYTES} bytes"));
    }

    let mut payload = vec![0u8; payload_len];
    let mut offset = 0usize;
    while offset < payload_len {
        let end = (offset + QUIC_STREAM_CHUNK_BYTES).min(payload_len);
        read_exact_timed(recv, &mut payload[offset..end], read_timeout).await?;
        offset = end;
    }
    Ok((header, payload))
}
