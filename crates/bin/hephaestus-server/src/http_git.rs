//! Streaming Git smart-HTTP (multi-repo `{repo}` validation + zero-buffering child pipes)
//! and Jujutsu OpLog handlers for [`crate::http`].

use crate::engine::HephaestusEngine;
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt as _;
use hephaestus_store::StoreError;
use serde::Deserialize;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

const PIPE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
pub(crate) struct GitServiceQuery {
    service: String,
}

pub(crate) fn map_store_err(err: StoreError) -> (StatusCode, String) {
    let code = match &err {
        StoreError::NotFound(_) => StatusCode::NOT_FOUND,
        StoreError::InvalidInput(_) | StoreError::Id(_) => StatusCode::BAD_REQUEST,
        StoreError::Conflict(_) | StoreError::ChainViolation(_) => StatusCode::CONFLICT,
        StoreError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, err.to_string())
}

pub(crate) async fn list_jj_ops(
    State(eng): State<Arc<HephaestusEngine>>,
) -> Result<Json<Vec<hephaestus_jj::JjOpSummary>>, (StatusCode, String)> {
    eng.list_jj_ops(50).await.map(Json).map_err(map_store_err)
}

pub(crate) async fn git_info_refs(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(repo): Path<String>,
    Query(q): Query<GitServiceQuery>,
) -> Result<Response, (StatusCode, String)> {
    let root = eng.resolve_jj_repo(&repo).map_err(map_store_err)?;
    let (ctype, body) = eng
        .git_bridge()
        .info_refs(&root, &q.service)
        .await
        .map_err(map_store_err)?;
    let mut resp = body.into_response();
    if let Ok(hv) = HeaderValue::from_str(&ctype) {
        resp.headers_mut().insert(header::CONTENT_TYPE, hv);
    }
    Ok(resp)
}

async fn pump_body_to_stdin(
    body: Body,
    mut stdin: tokio::process::ChildStdin,
) -> Result<(), String> {
    let mut stream = body.into_data_stream();
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|e| format!("read http body chunk: {e}"))?;
        stdin
            .write_all(&chunk)
            .await
            .map_err(|e| format!("write git stdin: {e}"))?;
    }
    stdin
        .shutdown()
        .await
        .map_err(|e| format!("close git stdin: {e}"))?;
    Ok(())
}

/// Streams `POST /git/{repo}/git-upload-pack` request & packfile response via async child pipes.
pub(crate) async fn git_upload_pack(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(repo): Path<String>,
    body: Body,
) -> Result<Response, (StatusCode, String)> {
    let root = eng.resolve_jj_repo(&repo).map_err(map_store_err)?;
    let git_dir = eng
        .git_bridge()
        .resolve_git_dir(&root)
        .await
        .map_err(map_store_err)?;
    let mut child = Command::new("git")
        .args(["upload-pack", "--stateless-rpc"])
        .arg(&git_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn git upload-pack: {e}"),
            )
        })?;

    if let Some(stdin) = child.stdin.take() {
        tokio::spawn(async move {
            let _ = pump_body_to_stdin(body, stdin).await;
        });
    }
    let stdout = child.stdout.take().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "git upload-pack missing stdout pipe".into(),
    ))?;

    let out_stream = futures::stream::unfold(
        (stdout, Some(child), vec![0u8; PIPE_CHUNK_BYTES]),
        |(mut reader, mut child_opt, mut buf)| async move {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    if let Some(mut c) = child_opt.take() {
                        let _ = c.wait().await;
                    }
                    None
                }
                Ok(n) => {
                    let chunk = Bytes::copy_from_slice(&buf[..n]);
                    Some((Ok::<Bytes, std::io::Error>(chunk), (reader, child_opt, buf)))
                }
                Err(err) => {
                    if let Some(mut c) = child_opt.take() {
                        let _ = c.kill().await;
                    }
                    Some((Err(err), (reader, child_opt, buf)))
                }
            }
        },
    );

    let mut resp = Body::from_stream(out_stream).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-upload-pack-result"),
    );
    Ok(resp)
}

/// Streams incoming packfile into `git-receive-pack`, imports pushed refs into `jj` OpLog,
/// syncs objects into CAS, and notifies [`hephaestus_store::WebhookSink`].
pub(crate) async fn git_receive_pack(
    State(eng): State<Arc<HephaestusEngine>>,
    Path(repo): Path<String>,
    body: Body,
) -> Result<Response, (StatusCode, String)> {
    let root = eng.resolve_jj_repo(&repo).map_err(map_store_err)?;
    let git_dir = eng
        .git_bridge()
        .resolve_git_dir(&root)
        .await
        .map_err(map_store_err)?;
    let mut child = Command::new("git")
        .args(["receive-pack", "--stateless-rpc"])
        .arg(&git_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn git receive-pack: {e}"),
            )
        })?;

    let stdin = child.stdin.take().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "git receive-pack missing stdin pipe".into(),
    ))?;
    let mut stdout = child.stdout.take().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "git receive-pack missing stdout pipe".into(),
    ))?;
    let mut stderr = child.stderr.take().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "git receive-pack missing stderr pipe".into(),
    ))?;

    let feed = pump_body_to_stdin(body, stdin);
    let read_out = async move {
        let mut out = Vec::new();
        stdout
            .read_to_end(&mut out)
            .await
            .map_err(|e| format!("read git receive-pack stdout: {e}"))?;
        Ok::<Vec<u8>, String>(out)
    };
    let read_err = async move {
        let mut err_buf = Vec::new();
        let _ = stderr.read_to_end(&mut err_buf).await;
        Ok::<Vec<u8>, String>(err_buf)
    };

    let (_, out_bytes, err_bytes) = tokio::try_join!(feed, read_out, read_err)
        .map_err(|msg| (StatusCode::INTERNAL_SERVER_ERROR, msg))?;
    let status = child.wait().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("wait git receive-pack: {e}"),
        )
    })?;
    if !status.success() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "git receive-pack failed: {}",
                String::from_utf8_lossy(&err_bytes).trim()
            ),
        ));
    }

    eng.git_bridge()
        .import_git_refs_into_jj(&root)
        .await
        .map_err(map_store_err)?;
    eng.sync_git_push_to_cas_and_notify(&repo, &root)
        .await
        .map_err(map_store_err)?;

    let mut resp = out_bytes.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-receive-pack-result"),
    );
    Ok(resp)
}
