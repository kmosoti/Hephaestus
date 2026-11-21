//! Pure-IPv6 HTTP/1.1 REST & Git smart-HTTP compatibility bridge over [`HephaestusEngine`].

use crate::engine::HephaestusEngine;
use crate::http_git::{
    git_info_refs, git_receive_pack, git_upload_pack, list_jj_ops, map_store_err as map_err,
};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use hephaestus_core::{
    ChangeId, CommitId, DecisionDraft, ObservationDraft, ObservationFilter, ObservationKind, OpId,
    RepoId,
};
use hephaestus_store::CommitRef;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

/// Query parameters for filtering Decision Log records.
#[derive(Deserialize)]
pub struct DecisionQueryParams {
    /// Optional Jujutsu `ChangeId` filter.
    pub change_id: Option<String>,
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

/// Builds the Axum HTTP/1.1 compatibility router over [`HephaestusEngine`].
pub fn build_http_router(engine: Arc<HephaestusEngine>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/stats", get(get_stats))
        .route("/v1/flush", post(post_flush))
        .route("/v1/blobs", post(put_blob))
        .route("/v1/blobs/{hash}", get(get_blob))
        .route("/v1/push", post(push_commit))
        .route("/v1/refs/{repo}", get(list_refs))
        .route("/v1/decisions", post(append_decision))
        .route("/v1/decisions/{repo}", get(list_decisions))
        .route("/v1/decisions/{repo}/verify", get(verify_decisions))
        .route("/v1/observations", post(append_observation))
        .route("/v1/observations/{repo}", get(query_observations))
        .route("/v1/observations/{repo}/verify", get(verify_observations))
        .route("/v1/jj/ops", get(list_jj_ops))
        .route("/git/{repo}/info/refs", get(git_info_refs))
        .route("/git/{repo}/git-upload-pack", post(git_upload_pack))
        .route("/git/{repo}/git-receive-pack", post(git_receive_pack))
        .with_state(engine)
}

async fn health(State(eng): State<Arc<HephaestusEngine>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "hephaestus-server",
        "backend": eng.backend_kind()
    }))
}

async fn get_stats(
    State(eng): State<Arc<HephaestusEngine>>,
) -> Result<Json<StatsResp>, (StatusCode, String)> {
    let (s, pending_bytes) = eng.stats().await.map_err(map_err)?;
    Ok(Json(StatsResp {
        backend: eng.backend_kind().to_owned(),
        inline_count: s.inline_count,
        packed_count: s.packed_count,
        bundle_count: s.bundle_count,
        idempotency_count: s.idempotency_count,
        decision_count: s.decision_count,
        observation_count: s.observation_count,
        pending_bytes,
    }))
}

async fn post_flush(
    State(eng): State<Arc<HephaestusEngine>>,
) -> Result<Json<FlushResp>, (StatusCode, String)> {
    let flushed_object_id = eng.flush_bundle().await.map_err(map_err)?;
    Ok(Json(FlushResp { flushed_object_id }))
}

async fn put_blob(
    State(eng): State<Arc<HephaestusEngine>>,
    Query(q): Query<BlobRepoQuery>,
    body: Bytes,
) -> Result<Json<BlobPutResp>, (StatusCode, String)> {
    let repo_id = RepoId::parse(q.repo.as_deref().unwrap_or("default"))
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let len = body.len();
    let (digest, deduplicated) = eng
        .put_blob_idempotent(&repo_id, body.to_vec(), q.pack.unwrap_or(false))
        .await
        .map_err(map_err)?;
    Ok(Json(BlobPutResp {
        hash_hex: digest.to_hex(),
        bytes: len,
        deduplicated,
    }))
}

async fn get_blob(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(hash): Path<String>,
) -> Result<Bytes, (StatusCode, String)> {
    match eng.get_blob_hex(&hash).await.map_err(map_err)? {
        Some(bytes) => Ok(Bytes::from(bytes)),
        None => Err((StatusCode::NOT_FOUND, "blob not found".into())),
    }
}

async fn push_commit(
    State(eng): State<Arc<HephaestusEngine>>,
    Json(commit): Json<CommitRef>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (ci_notified, deduplicated) = eng.push_ref_idempotent(&commit).await.map_err(map_err)?;
    Ok(Json(PushResp {
        accepted: true,
        ci_notified,
        deduplicated,
    }))
}

async fn list_refs(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(repo): Path<String>,
) -> Result<Json<Vec<CommitRef>>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    eng.list_refs(&repo_id).await.map(Json).map_err(map_err)
}

async fn append_decision(
    State(eng): State<Arc<HephaestusEngine>>,
    Json(body): Json<DecisionAppendBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let repo_id =
        RepoId::parse(&body.repo_id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let (record, deduplicated) = eng
        .append_decision_idempotent(&repo_id, body.draft)
        .await
        .map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "record": record, "deduplicated": deduplicated }),
    ))
}

async fn list_decisions(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(repo): Path<String>,
    Query(q): Query<DecisionQueryParams>,
) -> Result<Json<Vec<hephaestus_core::DecisionRecord>>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let ch = q
        .change_id
        .as_deref()
        .map(ChangeId::parse)
        .transpose()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    eng.list_decisions(&repo_id, ch.as_ref())
        .await
        .map(Json)
        .map_err(map_err)
}

async fn verify_decisions(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(repo): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let verified_count = eng.verify_decisions(&repo_id).await.map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "verified_count": verified_count }),
    ))
}

async fn append_observation(
    State(eng): State<Arc<HephaestusEngine>>,
    Json(body): Json<ObservationAppendBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let repo_id =
        RepoId::parse(&body.repo_id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let (record, deduplicated) = eng
        .append_observation_idempotent(&repo_id, body.draft)
        .await
        .map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "record": record, "deduplicated": deduplicated }),
    ))
}

async fn query_observations(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(repo): Path<String>,
    Query(q): Query<ObservationQueryParams>,
) -> Result<Json<Vec<hephaestus_core::ObservationRecord>>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let filter = ObservationFilter {
        change_id: q
            .change_id
            .as_deref()
            .map(ChangeId::parse)
            .transpose()
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        commit_id: q
            .commit_id
            .as_deref()
            .map(CommitId::parse)
            .transpose()
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        op_id: q
            .op_id
            .as_deref()
            .map(OpId::parse)
            .transpose()
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        kind: q.kind,
        passed: q.passed,
        since_seq: q.since_seq,
        limit: q.limit,
    };
    eng.query_observations(&repo_id, &filter)
        .await
        .map(Json)
        .map_err(map_err)
}

async fn verify_observations(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(repo): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    eng.verify_observations(&repo_id)
        .await
        .map(|verified_count| Json(serde_json::json!({ "verified_count": verified_count })))
        .map_err(map_err)
}
