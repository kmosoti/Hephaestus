//! Sanitized HTTP/QUIC error mapping with opaque request references and redacted logs.

use axum::http::StatusCode;
use hephaestus_store::StoreError;
use std::sync::atomic::{AtomicU64, Ordering};

static ERROR_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_error_ref() -> String {
    format!("err-{:016x}", ERROR_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// Redacts bearer/OAuth tokens and truncates diagnostics to a single bounded log line.
pub(crate) fn redact_sensitive(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(256)
        .collect();
    let lower = sanitized.to_ascii_lowercase();
    let mut out = sanitized.clone();
    if let Some(pos) = lower.find("bearer ") {
        let start = pos + "bearer ".len();
        let end = sanitized[start..]
            .find(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .map_or(sanitized.len(), |off| start + off);
        out.replace_range(start..end, "<redacted>");
    }
    for key in ["access_token=", "refresh_token="] {
        let check = out.to_ascii_lowercase();
        if let Some(pos) = check.find(key) {
            let start = pos + key.len();
            let end = out[start..]
                .find(|c: char| c == '&' || c.is_whitespace())
                .map_or(out.len(), |off| start + off);
            out.replace_range(start..end, "<redacted>");
        }
    }
    out
}

/// Maps internal [`StoreError`] to a stable external `(StatusCode, code, message)` without
/// disclosing filesystem paths, OS errors, SQLite internals, or upstream provider payloads.
pub(crate) fn sanitize_store_error(err: &StoreError) -> (StatusCode, &'static str, String) {
    let err_ref = next_error_ref();
    let (status, code, public_msg) = match err {
        StoreError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found", "resource not found"),
        StoreError::InvalidInput(_) => (StatusCode::BAD_REQUEST, "invalid_input", "invalid input"),
        StoreError::Id(_) => (
            StatusCode::BAD_REQUEST,
            "invalid_identifier",
            "invalid identifier",
        ),
        StoreError::Conflict(_) => (StatusCode::CONFLICT, "conflict", "resource conflict"),
        StoreError::ChainViolation(_) => (
            StatusCode::CONFLICT,
            "chain_violation",
            "integrity chain verification failed",
        ),
        StoreError::Bundle(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "bundle_error",
            "bundle format or integrity error",
        ),
        StoreError::RateLimited(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "request rate limited",
        ),
        StoreError::Serialization(_) => (
            StatusCode::BAD_REQUEST,
            "serialization_error",
            "malformed serialized payload",
        ),
        StoreError::Backend(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "internal storage error",
        ),
    };
    eprintln!(
        "[hephaestus] ref={err_ref} status={} code={code} detail={}",
        status.as_u16(),
        redact_sensitive(&err.to_string())
    );
    (status, code, format!("{public_msg} (ref={err_ref})"))
}

/// Logs `detail` internally and returns a sanitized `400 Bad Request` response.
pub(crate) fn sanitize_bad_request(public_msg: &str, detail: &str) -> (StatusCode, String) {
    let err_ref = next_error_ref();
    eprintln!(
        "[hephaestus] ref={err_ref} status=400 detail={}",
        redact_sensitive(detail)
    );
    (
        StatusCode::BAD_REQUEST,
        format!("{public_msg} (ref={err_ref})"),
    )
}

/// Logs `detail` internally and returns a sanitized HTTP status response.
pub(crate) fn sanitize_http_failure(
    status: StatusCode,
    public_msg: &str,
    detail: &str,
) -> (StatusCode, String) {
    let err_ref = next_error_ref();
    eprintln!(
        "[hephaestus] ref={err_ref} status={} detail={}",
        status.as_u16(),
        redact_sensitive(detail)
    );
    (status, format!("{public_msg} (ref={err_ref})"))
}

/// Logs `detail` internally and returns a sanitized QUIC error message.
pub(crate) fn sanitize_quic_error(public_msg: &str, detail: &str) -> String {
    let err_ref = next_error_ref();
    eprintln!(
        "[hephaestus-quic] ref={err_ref} detail={}",
        redact_sensitive(detail)
    );
    format!("{public_msg} (ref={err_ref})")
}
