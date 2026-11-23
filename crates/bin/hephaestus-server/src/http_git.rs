//! Streaming Git smart-HTTP with bounded concurrency, body/output caps, `kill_on_drop`,
//! deadlines, and sanitized errors for [`crate::http`].

use crate::error_map::{sanitize_http_failure, sanitize_store_error};
use crate::http::HttpBridgeState;
use crate::http_git_io::{
    AbortOnDrop, PIPE_CHUNK_BYTES, PumpError, acquire_git_permit, check_content_length,
    pump_body_to_stdin, read_bounded_stderr, read_bounded_stdout,
};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use hephaestus_store::StoreError;
use serde::Deserialize;
use std::process::Stdio;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;
use tokio::sync::oneshot;

#[derive(Deserialize)]
pub(crate) struct GitServiceQuery {
    service: String,
}

pub(crate) fn map_store_err(err: StoreError) -> (StatusCode, String) {
    let (code, _, msg) = sanitize_store_error(&err);
    (code, msg)
}

pub(crate) async fn list_jj_ops(
    State(state): State<HttpBridgeState>,
) -> Result<Json<Vec<hephaestus_jj::JjOpSummary>>, (StatusCode, String)> {
    state
        .eng
        .list_jj_ops(50)
        .await
        .map(Json)
        .map_err(map_store_err)
}

pub(crate) async fn git_info_refs(
    State(state): State<HttpBridgeState>,
    Path(repo): Path<String>,
    Query(q): Query<GitServiceQuery>,
) -> Result<Response, (StatusCode, String)> {
    let _git_permit = acquire_git_permit(&state)?;
    let root = state.eng.resolve_jj_repo(&repo).map_err(map_store_err)?;
    let (ctype, body) = state
        .eng
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

/// Streams `POST /git/{repo}/git-upload-pack` request & packfile response via bounded child pipes.
pub(crate) async fn git_upload_pack(
    State(state): State<HttpBridgeState>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, (StatusCode, String)> {
    check_content_length(&headers, state.max_body_bytes)?;
    let git_permit = acquire_git_permit(&state)?;
    let root = state.eng.resolve_jj_repo(&repo).map_err(map_store_err)?;
    let git_dir = state
        .eng
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
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            sanitize_http_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "git backend error",
                &format!("spawn git upload-pack: {e}"),
            )
        })?;

    let deadline = tokio::time::Instant::now() + state.request_timeout;
    let max_body = state.max_body_bytes;
    let (pump_fail_tx, pump_fail_rx) = oneshot::channel::<()>();
    let pump_guard = child.stdin.take().map(|stdin| {
        AbortOnDrop(tokio::spawn(async move {
            if pump_body_to_stdin(body, stdin, max_body, deadline)
                .await
                .is_err()
            {
                let _ = pump_fail_tx.send(());
            }
        }))
    });
    let stdout = child.stdout.take().ok_or_else(|| {
        sanitize_http_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git backend error",
            "git upload-pack missing stdout pipe",
        )
    })?;

    let out_stream = futures::stream::unfold(
        (
            stdout,
            Some(child),
            vec![0u8; PIPE_CHUNK_BYTES],
            Some(git_permit),
            pump_guard,
            pump_fail_rx,
            deadline,
        ),
        |(mut reader, mut child_opt, mut buf, permit, pump, mut fail_rx, dl)| async move {
            if fail_rx.try_recv().is_ok() {
                if let Some(mut c) = child_opt.take() {
                    let _ = c.kill().await;
                    let _ = c.wait().await;
                }
                return Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "git upload-pack request exceeded limits",
                    )),
                    (reader, None, buf, None, None, fail_rx, dl),
                ));
            }
            match tokio::time::timeout_at(dl, reader.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    if let Some(mut c) = child_opt.take() {
                        let _ = c.wait().await;
                    }
                    drop((permit, pump));
                    None
                }
                Ok(Ok(n)) => {
                    let chunk = Bytes::copy_from_slice(&buf[..n]);
                    Some((
                        Ok::<Bytes, std::io::Error>(chunk),
                        (reader, child_opt, buf, permit, pump, fail_rx, dl),
                    ))
                }
                Ok(Err(err)) => {
                    if let Some(mut c) = child_opt.take() {
                        let _ = c.kill().await;
                        let _ = c.wait().await;
                    }
                    drop((permit, pump));
                    Some((Err(err), (reader, None, buf, None, None, fail_rx, dl)))
                }
                Err(_) => {
                    if let Some(mut c) = child_opt.take() {
                        let _ = c.kill().await;
                        let _ = c.wait().await;
                    }
                    drop((permit, pump));
                    Some((
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "git upload-pack timed out",
                        )),
                        (reader, None, buf, None, None, fail_rx, dl),
                    ))
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

/// Streams incoming packfile into `git-receive-pack` with strict byte/time/output bounds,
/// imports pushed refs into `jj` OpLog, syncs objects into CAS, and notifies `WebhookSink`.
pub(crate) async fn git_receive_pack(
    State(state): State<HttpBridgeState>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, (StatusCode, String)> {
    check_content_length(&headers, state.max_body_bytes)?;
    let _git_permit = acquire_git_permit(&state)?;
    let root = state.eng.resolve_jj_repo(&repo).map_err(map_store_err)?;
    let git_dir = state
        .eng
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
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            sanitize_http_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "git backend error",
                &format!("spawn git receive-pack: {e}"),
            )
        })?;

    let stdin = child.stdin.take().ok_or_else(|| {
        sanitize_http_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git backend error",
            "git receive-pack missing stdin pipe",
        )
    })?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        sanitize_http_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git backend error",
            "git receive-pack missing stdout pipe",
        )
    })?;
    let mut stderr = child.stderr.take().ok_or_else(|| {
        sanitize_http_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git backend error",
            "git receive-pack missing stderr pipe",
        )
    })?;

    let deadline = tokio::time::Instant::now() + state.request_timeout;
    let max_body = state.max_body_bytes;
    let run = async {
        let feed = async move {
            pump_body_to_stdin(body, stdin, max_body, deadline)
                .await
                .map_err(|e| match e {
                    PumpError::TooLarge => (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!("git receive-pack request exceeded {max_body} bytes"),
                    ),
                    PumpError::Io(msg) => sanitize_http_failure(
                        StatusCode::BAD_REQUEST,
                        "git request stream error",
                        &msg,
                    ),
                })
        };
        let read_out = read_bounded_stdout(&mut stdout);
        let read_err = async move {
            Ok::<Vec<u8>, (StatusCode, String)>(read_bounded_stderr(&mut stderr).await)
        };
        tokio::try_join!(feed, read_out, read_err)
    };

    let (_, out_bytes, err_bytes) = match tokio::time::timeout_at(deadline, run).await {
        Ok(Ok(res)) => res,
        Ok(Err(err)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(err);
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(sanitize_http_failure(
                StatusCode::GATEWAY_TIMEOUT,
                "git receive-pack timed out",
                "git receive-pack deadline elapsed",
            ));
        }
    };

    let status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(Ok(st)) => st,
        Ok(Err(e)) => {
            return Err(sanitize_http_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "git backend error",
                &format!("wait git receive-pack: {e}"),
            ));
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(sanitize_http_failure(
                StatusCode::GATEWAY_TIMEOUT,
                "git receive-pack timed out",
                "git receive-pack wait deadline elapsed",
            ));
        }
    };
    if !status.success() {
        return Err(sanitize_http_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "git receive-pack failed",
            &String::from_utf8_lossy(&err_bytes),
        ));
    }

    state
        .eng
        .git_bridge()
        .import_git_refs_into_jj(&root)
        .await
        .map_err(map_store_err)?;
    state
        .eng
        .sync_git_push_to_cas_and_notify(&repo, &root)
        .await
        .map_err(map_store_err)?;

    let mut resp = out_bytes.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-receive-pack-result"),
    );
    Ok(resp)
}
