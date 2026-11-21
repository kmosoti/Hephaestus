//! Native-IPv6 HTTP/HTTPS transport for Google Drive v3 (`drive.file`), OAuth refresh,
//! and 8 MiB (256 KiB-aligned) chunked `Content-Range` resumable uploads.

use crate::drive_ops::{DriveHttpError, FileMetaResp, parse_308_next_offset, parse_retry_after_ms};
use hephaestus_core::{DRIVE_FILE_SCOPE, DriveOAuthFsm, MonoTime, SecretString};
use hephaestus_store::StoreError;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Default Google Drive v3 API base URL.
pub const GOOGLE_DRIVE_BASE_URL: &str = "https://www.googleapis.com";
/// Required Google Drive resumable chunk alignment (256 KiB).
pub const DRIVE_CHUNK_ALIGNMENT: usize = 256 * 1024;
/// Default resumable upload chunk size (8 MiB, 256 KiB-aligned).
pub const DRIVE_UPLOAD_CHUNK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct TokenRefreshResp {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default = "default_expires_in")]
    expires_in: u64,
}

const fn default_expires_in() -> u64 {
    3600
}

pub(crate) fn percent_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    out
}

fn encode_form_urlencoded(fields: &[(&str, String)]) -> String {
    let mut out = String::new();
    for (idx, (k, v)) in fields.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(&percent_encode(k));
        out.push('=');
        out.push_str(&percent_encode(v));
    }
    out
}

/// Native-IPv6 HTTPS client for Google Drive v3 resumable uploads, HTTP Range reads,
/// OAuth token refresh, and explicit DR `files.list` pagination.
#[derive(Clone)]
pub struct DriveHttpClient {
    base_url: String,
    oauth: Arc<RwLock<DriveOAuthFsm>>,
    token_endpoint_override: Option<String>,
    upload_chunk_bytes: usize,
    client: reqwest::Client,
}

impl DriveHttpClient {
    /// Creates a Drive HTTP client bound to `base_url` with a static `access_token` lease.
    pub fn new(
        base_url: impl Into<String>,
        access_token: SecretString,
    ) -> Result<Self, StoreError> {
        let mut fsm = DriveOAuthFsm::new("static-lease", "http://[::1]:0/cb", DRIVE_FILE_SCOPE)
            .map_err(|e| StoreError::InvalidInput(e.to_string()))?;
        fsm.apply_token_response(access_token, None, u64::MAX / 2000, MonoTime(0));
        Self::with_oauth_fsm(base_url, Arc::new(RwLock::new(fsm)), None)
    }

    /// Creates a Drive HTTP client driven by a shared [`DriveOAuthFsm`] with automatic refresh.
    pub fn with_oauth_fsm(
        base_url: impl Into<String>,
        oauth: Arc<RwLock<DriveOAuthFsm>>,
        token_endpoint_override: Option<String>,
    ) -> Result<Self, StoreError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| StoreError::Backend(format!("drive reqwest client: {e}")))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            oauth,
            token_endpoint_override,
            upload_chunk_bytes: DRIVE_UPLOAD_CHUNK_BYTES,
            client,
        })
    }

    /// Overrides the 256 KiB-aligned resumable upload chunk size (default 8 MiB).
    #[must_use]
    pub fn with_upload_chunk_bytes(mut self, chunk_bytes: usize) -> Self {
        let aligned = (chunk_bytes / DRIVE_CHUNK_ALIGNMENT).max(1) * DRIVE_CHUNK_ALIGNMENT;
        self.upload_chunk_bytes = aligned;
        self
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Returns a valid `Bearer ...` Authorization header, refreshing via [`DriveOAuthFsm`] if expired.
    pub async fn bearer_header(
        &self,
        now: MonoTime,
        force_refresh: bool,
    ) -> Result<String, DriveHttpError> {
        if !force_refresh && let Some(tok) = self.oauth.read().await.valid_access_token(now) {
            return Ok(format!("Bearer {}", tok.expose_for_http_header()));
        }
        self.refresh_access_token(now).await
    }

    /// Executes a refresh-token exchange via [`DriveOAuthFsm`] and stores the refreshed lease.
    pub async fn refresh_access_token(&self, now: MonoTime) -> Result<String, DriveHttpError> {
        let form_req = {
            let guard = self.oauth.read().await;
            guard.build_refresh_request().map_err(|e| DriveHttpError {
                status: 401,
                retry_after_ms: None,
                detail: e.to_string(),
            })?
        };
        let endpoint = self
            .token_endpoint_override
            .as_deref()
            .unwrap_or(form_req.endpoint);
        let form_body = encode_form_urlencoded(&form_req.form_fields);
        let resp = self
            .client
            .post(endpoint)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form_body)
            .send()
            .await
            .map_err(|e| DriveHttpError {
                status: 0,
                retry_after_ms: None,
                detail: format!("oauth refresh transport error: {e}"),
            })?;
        let status = resp.status().as_u16();
        let retry_after_ms = parse_retry_after_ms(resp.headers());
        if status != 200 {
            let detail = resp.text().await.unwrap_or_default();
            return Err(DriveHttpError {
                status,
                retry_after_ms,
                detail,
            });
        }
        let parsed: TokenRefreshResp = resp.json().await.map_err(|e| DriveHttpError {
            status: 502,
            retry_after_ms: None,
            detail: format!("oauth refresh json parse: {e}"),
        })?;
        let header = format!("Bearer {}", parsed.access_token);
        let mut guard = self.oauth.write().await;
        guard.apply_token_response(
            SecretString::new(parsed.access_token),
            parsed.refresh_token.map(SecretString::new),
            parsed.expires_in,
            now,
        );
        Ok(header)
    }

    /// Performs a resumable Drive v3 upload in 8 MiB (256 KiB-aligned) `Content-Range` chunks,
    /// recovering from `308 Resume Incomplete` using the server's `Range:` offset.
    pub async fn upload_resumable(
        &self,
        bundle_name: &str,
        bytes: &[u8],
        auth: &str,
    ) -> Result<String, DriveHttpError> {
        let init_url = format!(
            "{}/upload/drive/v3/files?uploadType=resumable",
            self.base_url
        );
        let init_resp = self
            .client
            .post(&init_url)
            .header(reqwest::header::AUTHORIZATION, auth)
            .header("X-Upload-Content-Type", "application/zstd")
            .header("X-Upload-Content-Length", bytes.len().to_string())
            .json(&serde_json::json!({ "name": bundle_name, "mimeType": "application/zstd" }))
            .send()
            .await
            .map_err(|e| DriveHttpError {
                status: 0,
                retry_after_ms: None,
                detail: format!("drive init transport error: {e}"),
            })?;
        let status = init_resp.status().as_u16();
        let retry_after_ms = parse_retry_after_ms(init_resp.headers());
        if status != 200 {
            let detail = init_resp.text().await.unwrap_or_default();
            return Err(DriveHttpError {
                status,
                retry_after_ms,
                detail,
            });
        }
        let session_uri = init_resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| DriveHttpError {
                status: 502,
                retry_after_ms: None,
                detail: "Drive resumable session missing Location header".into(),
            })?
            .to_owned();
        let put_url = if session_uri.starts_with("http") {
            session_uri
        } else {
            format!("{}{}", self.base_url, session_uri)
        };

        let total = bytes.len();
        let mut offset = 0usize;
        loop {
            let end = offset.saturating_add(self.upload_chunk_bytes).min(total);
            let chunk = &bytes[offset..end];
            let content_range = if total == 0 {
                "bytes */0".to_owned()
            } else {
                format!("bytes {offset}-{}/{total}", end - 1)
            };
            let put_resp = self
                .client
                .put(&put_url)
                .header(reqwest::header::AUTHORIZATION, auth)
                .header(reqwest::header::CONTENT_TYPE, "application/zstd")
                .header(reqwest::header::CONTENT_RANGE, content_range)
                .body(chunk.to_vec())
                .send()
                .await
                .map_err(|e| DriveHttpError {
                    status: 0,
                    retry_after_ms: None,
                    detail: format!("drive chunk put transport error: {e}"),
                })?;
            let put_status = put_resp.status().as_u16();
            let put_retry = parse_retry_after_ms(put_resp.headers());
            if put_status == 308 {
                let next = parse_308_next_offset(put_resp.headers()).unwrap_or(end);
                if next >= total {
                    return Err(DriveHttpError {
                        status: 502,
                        retry_after_ms: None,
                        detail: "Drive returned 308 at EOF without finalizing file".into(),
                    });
                }
                offset = next;
                continue;
            }
            if put_status != 200 && put_status != 201 {
                let detail = put_resp.text().await.unwrap_or_default();
                return Err(DriveHttpError {
                    status: put_status,
                    retry_after_ms: put_retry,
                    detail,
                });
            }
            let parsed: FileMetaResp = put_resp.json().await.map_err(|e| DriveHttpError {
                status: 502,
                retry_after_ms: None,
                detail: format!("drive json parse error: {e}"),
            })?;
            return Ok(parsed.id);
        }
    }
}
