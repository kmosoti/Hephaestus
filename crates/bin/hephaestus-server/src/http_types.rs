//! Request/response DTOs and security configuration for the HTTP/1.1 compatibility bridge.

use crate::http_auth::HttpAuthMode;
use hephaestus_core::{DecisionDraft, ObservationDraft, ObservationKind};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Maximum HTTP request body size accepted by REST and Git smart-HTTP handlers (`64 MiB`).
pub const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum concurrent HTTP requests processed simultaneously.
pub const DEFAULT_HTTP_MAX_CONCURRENCY: usize = 64;
/// Default maximum concurrent `git` child processes spawned by the HTTP bridge.
pub const DEFAULT_MAX_GIT_CHILDREN: usize = 16;
/// Default request/process timeout for HTTP endpoints (`60s`).
pub const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Configuration governing HTTP authentication, concurrency admission, body caps, and deadlines.
#[derive(Clone, Debug)]
pub struct HttpBridgeConfig {
    /// Bearer authentication mode for non-`/health` routes.
    pub auth: HttpAuthMode,
    /// Maximum concurrent in-flight HTTP requests.
    pub max_concurrency: usize,
    /// Maximum concurrent `git` child processes.
    pub max_git_children: usize,
    /// Maximum HTTP request body bytes (`<= 64 MiB`).
    pub max_body_bytes: usize,
    /// Request and child-process execution deadline.
    pub request_timeout: Duration,
}

impl Default for HttpBridgeConfig {
    fn default() -> Self {
        Self {
            auth: HttpAuthMode::FailClosed,
            max_concurrency: DEFAULT_HTTP_MAX_CONCURRENCY,
            max_git_children: DEFAULT_MAX_GIT_CHILDREN,
            max_body_bytes: MAX_HTTP_BODY_BYTES,
            request_timeout: DEFAULT_HTTP_REQUEST_TIMEOUT,
        }
    }
}

/// HTTP response after storing a single CAS blob.
#[derive(Serialize, Deserialize)]
pub struct BlobPutResp {
    /// BLAKE3 hex digest of the stored blob.
    pub hash_hex: String,
    /// Uncompressed payload byte length.
    pub bytes: usize,
    /// Whether the blob already existed in the catalog or idempotency ledger.
    pub deduplicated: bool,
}

/// HTTP response after pushing a bookmark ref update.
#[derive(Serialize, Deserialize)]
pub struct PushResp {
    /// Whether the ref update was accepted.
    pub accepted: bool,
    /// Whether a configured webhook endpoint was notified.
    pub ci_notified: bool,
    /// Whether this push operation was idempotently deduplicated.
    pub deduplicated: bool,
}

/// HTTP response after flushing packed `GRNB0002` staging bundles.
#[derive(Serialize, Deserialize)]
pub struct FlushResp {
    /// Backing object key created for the flushed bundle, if any.
    pub flushed_object_id: Option<String>,
}

/// HTTP response summarizing storage, decision log, and observation log counts.
#[derive(Serialize, Deserialize)]
pub struct StatsResp {
    /// Active storage backend name.
    pub backend: String,
    /// Inline blob count.
    pub inline_count: u64,
    /// Packed blob count.
    pub packed_count: u64,
    /// Packed `GRNB0002` bundle count.
    pub bundle_count: u64,
    /// Idempotency ledger entry count.
    pub idempotency_count: u64,
    /// Append-only decision log entry count.
    pub decision_count: u64,
    /// Append-only observation log entry count.
    pub observation_count: u64,
    /// Pending uncompressed bytes awaiting flush.
    pub pending_bytes: usize,
}

/// Request body to append a hash-chained Decision Log record.
#[derive(Deserialize)]
pub struct DecisionAppendBody {
    /// Target repository identifier.
    pub repo_id: String,
    /// Decision draft fields.
    pub draft: DecisionDraft,
}

/// Request body to append an Orthogonal Observation Log record.
#[derive(Deserialize)]
pub struct ObservationAppendBody {
    /// Target repository identifier.
    pub repo_id: String,
    /// Observation draft fields.
    pub draft: ObservationDraft,
}

/// Query parameters for filtering and paginating Decision Log records.
#[derive(Deserialize)]
pub struct DecisionQueryParams {
    /// Optional Jujutsu `ChangeId` filter.
    pub change_id: Option<String>,
    /// Minimum inclusive sequence number (`seq >= since_seq`).
    pub since_seq: Option<u64>,
    /// Maximum records to return (capped at `MAX_LOG_PAGE_LIMIT`).
    pub limit: Option<usize>,
}

/// Query parameters for filtering Orthogonal Observation Log records.
#[derive(Deserialize)]
pub struct ObservationQueryParams {
    /// Optional Jujutsu `ChangeId` filter.
    pub change_id: Option<String>,
    /// Optional Jujutsu `CommitId` filter.
    pub commit_id: Option<String>,
    /// Optional Jujutsu `OpId` filter.
    pub op_id: Option<String>,
    /// Optional observation kind filter.
    pub kind: Option<ObservationKind>,
    /// Optional pass/fail outcome filter.
    pub passed: Option<bool>,
    /// Minimum inclusive sequence number (`seq >= since_seq`).
    pub since_seq: Option<u64>,
    /// Maximum records to return.
    pub limit: Option<usize>,
}

/// Query parameters for `POST /v1/blobs`.
#[derive(Deserialize)]
pub struct BlobRepoQuery {
    /// Repository identifier (defaults to `"default"`).
    pub repo: Option<String>,
    /// Hint indicating whether small blobs should enter bundle staging.
    pub pack: Option<bool>,
}
