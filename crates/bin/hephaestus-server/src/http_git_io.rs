//! Bounded pipe/body/output streaming helpers for [`crate::http_git`].

use crate::error_map::sanitize_http_failure;
use crate::http::HttpBridgeState;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use futures::StreamExt as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::OwnedSemaphorePermit;

pub(crate) const PIPE_CHUNK_BYTES: usize = 64 * 1024;
pub(crate) const MAX_GIT_RECEIVE_STDOUT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;

pub(crate) enum PumpError {
    TooLarge,
    Io(String),
}

pub(crate) struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn check_content_length(
    headers: &HeaderMap,
    max_bytes: usize,
) -> Result<(), (StatusCode, String)> {
    if let Some(raw) = headers.get(header::CONTENT_LENGTH)
        && let Ok(text) = raw.to_str()
        && let Ok(len) = text.trim().parse::<u64>()
        && len > max_bytes as u64
    {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body exceeds {max_bytes} byte limit"),
        ));
    }
    Ok(())
}

pub(crate) fn acquire_git_permit(
    state: &HttpBridgeState,
) -> Result<OwnedSemaphorePermit, (StatusCode, String)> {
    Arc::clone(&state.git_sem).try_acquire_owned().map_err(|_| {
        sanitize_http_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "git worker capacity exhausted",
            "git child concurrency semaphore full",
        )
    })
}

pub(crate) async fn pump_body_to_stdin(
    body: Body,
    mut stdin: tokio::process::ChildStdin,
    max_bytes: usize,
    deadline: tokio::time::Instant,
) -> Result<(), PumpError> {
    let mut stream = body.into_data_stream();
    let mut total = 0usize;
    loop {
        let next = tokio::time::timeout_at(deadline, stream.next())
            .await
            .map_err(|_| PumpError::Io("http body stream timed out".into()))?;
        let Some(chunk_res) = next else {
            break;
        };
        let chunk = chunk_res.map_err(|e| PumpError::Io(format!("read http body chunk: {e}")))?;
        total = total.saturating_add(chunk.len());
        if total > max_bytes {
            return Err(PumpError::TooLarge);
        }
        tokio::time::timeout_at(deadline, stdin.write_all(&chunk))
            .await
            .map_err(|_| PumpError::Io("write git stdin timed out".into()))?
            .map_err(|e| PumpError::Io(format!("write git stdin: {e}")))?;
    }
    tokio::time::timeout_at(deadline, stdin.shutdown())
        .await
        .map_err(|_| PumpError::Io("close git stdin timed out".into()))?
        .map_err(|e| PumpError::Io(format!("close git stdin: {e}")))?;
    Ok(())
}

pub(crate) async fn read_bounded_stdout(
    stdout: &mut tokio::process::ChildStdout,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let mut out = Vec::new();
    let mut limited = stdout.take((MAX_GIT_RECEIVE_STDOUT_BYTES as u64) + 1);
    limited.read_to_end(&mut out).await.map_err(|e| {
        sanitize_http_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "git backend error",
            &format!("read git receive-pack stdout: {e}"),
        )
    })?;
    if out.len() > MAX_GIT_RECEIVE_STDOUT_BYTES {
        return Err(sanitize_http_failure(
            StatusCode::BAD_GATEWAY,
            "git receive-pack output exceeded limit",
            "git receive-pack stdout exceeded cap",
        ));
    }
    Ok(out)
}

pub(crate) async fn read_bounded_stderr(stderr: &mut tokio::process::ChildStderr) -> Vec<u8> {
    let mut err_buf = Vec::new();
    let mut limited = stderr.take(MAX_GIT_STDERR_BYTES as u64);
    let _ = limited.read_to_end(&mut err_buf).await;
    err_buf
}
