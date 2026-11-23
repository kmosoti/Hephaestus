//! Pure-IPv6 HTTP/1.1 REST & Git smart-HTTP compatibility bridge over [`HephaestusEngine`].

use crate::engine::HephaestusEngine;
use crate::error_map::{sanitize_bad_request, sanitize_http_failure};
use crate::http_auth::{HttpAuthMode, require_bearer_auth};
use crate::http_git::{
    git_info_refs, git_receive_pack, git_upload_pack, list_jj_ops, map_store_err as map_err,
};
use crate::http_types::{
    BlobPutResp, BlobRepoQuery, DecisionAppendBody, DecisionQueryParams, FlushResp,
    HttpBridgeConfig, MAX_HTTP_BODY_BYTES, ObservationAppendBody, ObservationQueryParams, PushResp,
    StatsResp,
};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hephaestus_core::{ChangeId, CommitId, ObservationFilter, OpId, RepoId};
use hephaestus_store::CommitRef;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub(crate) struct HttpBridgeState {
    pub(crate) eng: Arc<HephaestusEngine>,
    pub(crate) http_sem: Arc<Semaphore>,
    pub(crate) git_sem: Arc<Semaphore>,
    pub(crate) max_body_bytes: usize,
    pub(crate) request_timeout: Duration,
}

async fn admission_and_deadline(
    State(state): State<HttpBridgeState>,
    req: Request,
    next: Next,
) -> Response {
    let Ok(permit) = Arc::clone(&state.http_sem).try_acquire_owned() else {
        return sanitize_http_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "server busy",
            "http concurrency semaphore exhausted",
        )
        .into_response();
    };
    match tokio::time::timeout(state.request_timeout, next.run(req)).await {
        Ok(resp) => {
            drop(permit);
            resp
        }
        Err(_) => {
            drop(permit);
            sanitize_http_failure(
                StatusCode::GATEWAY_TIMEOUT,
                "request timed out",
                "http request exceeded deadline",
            )
            .into_response()
        }
    }
}

/// Builds a fail-closed HTTP router (rejects non-health requests until configured with auth).
pub fn build_http_router(engine: Arc<HephaestusEngine>) -> Router {
    build_http_router_with_config(engine, HttpBridgeConfig::default())
}

/// Builds an HTTP router authenticated by a Bearer token SHA-256 digest.
pub fn build_authenticated_http_router(
    engine: Arc<HephaestusEngine>,
    token_sha256: [u8; 32],
) -> Router {
    build_http_router_with_config(
        engine,
        HttpBridgeConfig {
            auth: HttpAuthMode::BearerSha256(token_sha256),
            ..HttpBridgeConfig::default()
        },
    )
}

/// Builds the Axum HTTP/1.1 compatibility router with explicit auth, concurrency, body, and deadline limits.
pub fn build_http_router_with_config(
    engine: Arc<HephaestusEngine>,
    config: HttpBridgeConfig,
) -> Router {
    let max_body = config.max_body_bytes.clamp(1024, MAX_HTTP_BODY_BYTES);
    let state = HttpBridgeState {
        eng: engine,
        http_sem: Arc::new(Semaphore::new(config.max_concurrency.max(1))),
        git_sem: Arc::new(Semaphore::new(config.max_git_children.max(1))),
        max_body_bytes: max_body,
        request_timeout: config.request_timeout,
    };

    let protected = Router::new()
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
        .layer(middleware::from_fn_with_state(
            config.auth,
            require_bearer_auth,
        ));

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .layer(DefaultBodyLimit::max(max_body))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admission_and_deadline,
        ))
        .with_state(state)
}

async fn health(State(state): State<HttpBridgeState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "hephaestus-server",
        "backend": state.eng.backend_kind()
    }))
}

async fn get_stats(
    State(state): State<HttpBridgeState>,
) -> Result<Json<StatsResp>, (StatusCode, String)> {
    let (s, pending_bytes) = state.eng.stats().await.map_err(map_err)?;
    Ok(Json(StatsResp {
        backend: state.eng.backend_kind().to_owned(),
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
    State(state): State<HttpBridgeState>,
) -> Result<Json<FlushResp>, (StatusCode, String)> {
    let flushed_object_id = state.eng.flush_bundle().await.map_err(map_err)?;
    Ok(Json(FlushResp { flushed_object_id }))
}

async fn put_blob(
    State(state): State<HttpBridgeState>,
    Query(q): Query<BlobRepoQuery>,
    body: Bytes,
) -> Result<Json<BlobPutResp>, (StatusCode, String)> {
    let repo_id = RepoId::parse(q.repo.as_deref().unwrap_or("default"))
        .map_err(|e| sanitize_bad_request("invalid repository identifier", &e.to_string()))?;
    let len = body.len();
    let (digest, deduplicated) = state
        .eng
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
    State(state): State<HttpBridgeState>,
    Path(hash): Path<String>,
) -> Result<Bytes, (StatusCode, String)> {
    match state.eng.get_blob_hex(&hash).await.map_err(map_err)? {
        Some(bytes) => Ok(Bytes::from(bytes)),
        None => Err((StatusCode::NOT_FOUND, "blob not found".into())),
    }
}

async fn push_commit(
    State(state): State<HttpBridgeState>,
    Json(commit): Json<CommitRef>,
) -> Result<Json<PushResp>, (StatusCode, String)> {
    let (ci_notified, deduplicated) = state
        .eng
        .push_ref_idempotent(&commit)
        .await
        .map_err(map_err)?;
    Ok(Json(PushResp {
        accepted: true,
        ci_notified,
        deduplicated,
    }))
}

async fn list_refs(
    State(state): State<HttpBridgeState>,
    Path(repo): Path<String>,
) -> Result<Json<Vec<CommitRef>>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo)
        .map_err(|e| sanitize_bad_request("invalid repository identifier", &e.to_string()))?;
    state
        .eng
        .list_refs(&repo_id)
        .await
        .map(Json)
        .map_err(map_err)
}

async fn append_decision(
    State(state): State<HttpBridgeState>,
    Json(body): Json<DecisionAppendBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&body.repo_id)
        .map_err(|e| sanitize_bad_request("invalid repository identifier", &e.to_string()))?;
    let (record, deduplicated) = state
        .eng
        .append_decision_idempotent(&repo_id, body.draft)
        .await
        .map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "record": record, "deduplicated": deduplicated }),
    ))
}

async fn list_decisions(
    State(state): State<HttpBridgeState>,
    Path(repo): Path<String>,
    Query(q): Query<DecisionQueryParams>,
) -> Result<Json<Vec<hephaestus_core::DecisionRecord>>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo)
        .map_err(|e| sanitize_bad_request("invalid repository identifier", &e.to_string()))?;
    let ch = q
        .change_id
        .as_deref()
        .map(ChangeId::parse)
        .transpose()
        .map_err(|e| sanitize_bad_request("invalid change_id", &e.to_string()))?;
    state
        .eng
        .query_decisions(&repo_id, ch.as_ref(), q.since_seq, q.limit)
        .await
        .map(Json)
        .map_err(map_err)
}

async fn verify_decisions(
    State(state): State<HttpBridgeState>,
    Path(repo): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo)
        .map_err(|e| sanitize_bad_request("invalid repository identifier", &e.to_string()))?;
    let verified_count = state
        .eng
        .verify_decisions(&repo_id)
        .await
        .map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "verified_count": verified_count }),
    ))
}

async fn append_observation(
    State(state): State<HttpBridgeState>,
    Json(body): Json<ObservationAppendBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&body.repo_id)
        .map_err(|e| sanitize_bad_request("invalid repository identifier", &e.to_string()))?;
    let (record, deduplicated) = state
        .eng
        .append_observation_idempotent(&repo_id, body.draft)
        .await
        .map_err(map_err)?;
    Ok(Json(
        serde_json::json!({ "record": record, "deduplicated": deduplicated }),
    ))
}

async fn query_observations(
    State(state): State<HttpBridgeState>,
    Path(repo): Path<String>,
    Query(q): Query<ObservationQueryParams>,
) -> Result<Json<Vec<hephaestus_core::ObservationRecord>>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo)
        .map_err(|e| sanitize_bad_request("invalid repository identifier", &e.to_string()))?;
    let filter = ObservationFilter {
        change_id: q
            .change_id
            .as_deref()
            .map(ChangeId::parse)
            .transpose()
            .map_err(|e| sanitize_bad_request("invalid change_id", &e.to_string()))?,
        commit_id: q
            .commit_id
            .as_deref()
            .map(CommitId::parse)
            .transpose()
            .map_err(|e| sanitize_bad_request("invalid commit_id", &e.to_string()))?,
        op_id: q
            .op_id
            .as_deref()
            .map(OpId::parse)
            .transpose()
            .map_err(|e| sanitize_bad_request("invalid op_id", &e.to_string()))?,
        kind: q.kind,
        passed: q.passed,
        since_seq: q.since_seq,
        limit: q.limit,
    };
    state
        .eng
        .query_observations(&repo_id, &filter)
        .await
        .map(Json)
        .map_err(map_err)
}

async fn verify_observations(
    State(state): State<HttpBridgeState>,
    Path(repo): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let repo_id = RepoId::parse(&repo)
        .map_err(|e| sanitize_bad_request("invalid repository identifier", &e.to_string()))?;
    state
        .eng
        .verify_observations(&repo_id)
        .await
        .map(|verified_count| Json(serde_json::json!({ "verified_count": verified_count })))
        .map_err(map_err)
}
