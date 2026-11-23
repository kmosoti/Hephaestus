//! HTTP/1.1 Bearer token loading (`O_NOFOLLOW` + `0o077` mode check) and constant-time
//! SHA-256 authentication middleware for non-health routes.

use crate::quic_spki::ct_eq_32;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::Path;

/// Maximum permitted HTTP auth token file size (`4 KiB`).
pub const MAX_HTTP_AUTH_TOKEN_FILE_BYTES: usize = 4096;

/// HTTP authentication policy for non-`/health` routes.
#[derive(Clone, Debug)]
pub enum HttpAuthMode {
    /// Require `Authorization: Bearer <token>` matching the stored SHA-256 digest.
    BearerSha256([u8; 32]),
    /// Explicit local-loopback test opt-in (`--allow-unauthenticated-loopback-http`).
    AllowUnauthenticatedLoopback,
    /// Fail-closed default rejecting all non-health requests until configured.
    FailClosed,
}

/// Reads an HTTP Bearer token file via `O_NOFOLLOW` (`#[cfg(unix)]`), verifies it is a regular
/// file with no group/other permissions (`mode & 0o077 == 0`), and returns its SHA-256 digest.
pub fn load_http_auth_token_hash(path: &Path) -> Result<[u8; 32], String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts
        .open(path)
        .map_err(|e| format!("open http auth token file `{}`: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("stat http auth token file `{}`: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "http auth token path `{}` is not a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode();
        if (mode & 0o077) != 0 {
            return Err(format!(
                "http auth token file `{}` has unsafe permissions ({mode:04o}); require no group/other access (e.g. 0600/0400)",
                path.display()
            ));
        }
    }
    if meta.len() > MAX_HTTP_AUTH_TOKEN_FILE_BYTES as u64 {
        return Err(format!(
            "http auth token file `{}` exceeds {MAX_HTTP_AUTH_TOKEN_FILE_BYTES} bytes",
            path.display()
        ));
    }

    let mut raw_buf = Vec::new();
    let mut limited = file.take((MAX_HTTP_AUTH_TOKEN_FILE_BYTES as u64) + 1);
    limited
        .read_to_end(&mut raw_buf)
        .map_err(|e| format!("read http auth token file `{}`: {e}", path.display()))?;
    if raw_buf.len() > MAX_HTTP_AUTH_TOKEN_FILE_BYTES {
        raw_buf.fill(0);
        return Err(format!(
            "http auth token file `{}` exceeds {MAX_HTTP_AUTH_TOKEN_FILE_BYTES} bytes",
            path.display()
        ));
    }
    let parsed = std::str::from_utf8(&raw_buf)
        .map_err(|_| "http auth token file must be valid UTF-8".to_owned());
    let hash_res = match parsed {
        Ok(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty()
                || trimmed
                    .bytes()
                    .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            {
                Err("http auth token must be a single non-empty token without whitespace or control characters".to_owned())
            } else {
                Ok(Sha256::digest(trimmed.as_bytes()).into())
            }
        }
        Err(e) => Err(e),
    };
    raw_buf.fill(0);
    hash_res
}

/// Extracts and SHA-256 hashes a `Bearer <token>` from `Authorization` headers.
pub(crate) fn parse_bearer_token_sha256(headers: &HeaderMap) -> Option<[u8; 32]> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let tok = token.trim();
    if tok.is_empty()
        || tok
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    Some(Sha256::digest(tok.as_bytes()).into())
}

fn unauthorized_response() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

/// Axum middleware enforcing HTTP Bearer authentication on all non-`/health` routes.
pub(crate) async fn require_bearer_auth(
    State(mode): State<HttpAuthMode>,
    req: Request,
    next: Next,
) -> Response {
    match mode {
        HttpAuthMode::AllowUnauthenticatedLoopback => next.run(req).await,
        HttpAuthMode::FailClosed => unauthorized_response(),
        HttpAuthMode::BearerSha256(expected) => {
            let Some(presented) = parse_bearer_token_sha256(req.headers()) else {
                return unauthorized_response();
            };
            if ct_eq_32(&presented, &expected) {
                next.run(req).await
            } else {
                unauthorized_response()
            }
        }
    }
}
