//! Structured Drive HTTP errors, response DTOs, header parsers, and file read/head/delete/list ops.

use crate::drive_http::{DriveHttpClient, percent_encode};
use bytes::Bytes;
use core::ops::Range;
use hephaestus_store::{ObjectMeta, StoreError};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct FileMetaResp {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) size: Option<String>,
}

#[derive(Deserialize)]
struct FileListResp {
    #[serde(default)]
    files: Vec<FileMetaResp>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

/// Summary of one Drive bundle returned by [`crate::GoogleDriveStore::list_bundles`] for DR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveBundleEntry {
    /// Google Drive `fileId`.
    pub object_id: String,
    /// Uploaded bundle object name.
    pub name: String,
    /// Size in bytes as reported by Drive.
    pub size_bytes: u64,
}

/// Structured HTTP error emitted by [`DriveHttpClient`] for quota/retry classification.
#[derive(Debug, Clone)]
pub struct DriveHttpError {
    /// HTTP status code (`0` for transport failure).
    pub status: u16,
    /// Parsed `Retry-After` delay in milliseconds if supplied by server.
    pub retry_after_ms: Option<u64>,
    /// Error body or transport detail.
    pub detail: String,
}

impl DriveHttpError {
    /// Returns `true` for HTTP `429`, `503`, transient `5xx`, transport `0`,
    /// or `403` rate-limit reasons (never permanent permission errors).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self.status {
            0 | 429 | 500 | 502 | 503 | 504 => true,
            403 => is_rate_limit_403(&self.detail),
            _ => false,
        }
    }

    /// Converts into [`StoreError`] without leaking raw upstream provider error bodies.
    #[must_use]
    pub fn into_store_error(self) -> StoreError {
        if self.status == 404 {
            return StoreError::NotFound("drive object not found".into());
        }
        if self.status == 429 || (self.status == 403 && is_rate_limit_403(&self.detail)) {
            return StoreError::RateLimited(format!("Drive HTTP {} rate limited", self.status));
        }
        StoreError::Backend(format!("Drive HTTP {} error", self.status))
    }
}

pub(crate) fn is_rate_limit_403(detail: &str) -> bool {
    const REASONS: &[&str] = &[
        "rateLimitExceeded",
        "userRateLimitExceeded",
        "sharingRateLimitExceeded",
        "dailyLimitExceeded",
        "backendError",
    ];
    REASONS.iter().any(|r| detail.contains(r))
}

pub(crate) fn parse_retry_after_ms(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let raw = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    raw.parse::<u64>()
        .ok()
        .map(|secs| secs.saturating_mul(1000))
}

pub(crate) fn parse_308_next_offset(headers: &reqwest::header::HeaderMap) -> Option<usize> {
    let raw = headers.get(reqwest::header::RANGE)?.to_str().ok()?.trim();
    let suffix = raw.strip_prefix("bytes=0-")?;
    suffix
        .parse::<usize>()
        .ok()
        .map(|end| end.saturating_add(1))
}

impl DriveHttpClient {
    /// Downloads raw media bytes directly by `fileId`, optionally scoped by HTTP `Range`.
    pub async fn download_bytes(
        &self,
        file_id: &str,
        range: Option<Range<u64>>,
        auth: &str,
    ) -> Result<Bytes, DriveHttpError> {
        if let Some(r) = &range
            && r.start >= r.end
        {
            return Ok(Bytes::new());
        }
        let url = format!("{}/drive/v3/files/{file_id}?alt=media", self.base_url());
        let mut req = self
            .client()
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, auth);
        if let Some(r) = &range {
            req = req.header(
                reqwest::header::RANGE,
                format!("bytes={}-{}", r.start, r.end - 1),
            );
        }
        let resp = req.send().await.map_err(|e| DriveHttpError {
            status: 0,
            retry_after_ms: None,
            detail: format!("drive download error: {e}"),
        })?;
        let status = resp.status().as_u16();
        let retry_after_ms = parse_retry_after_ms(resp.headers());
        if status != 200 && status != 206 {
            let detail = resp.text().await.unwrap_or_default();
            return Err(DriveHttpError {
                status,
                retry_after_ms,
                detail,
            });
        }
        let body = resp.bytes().await.map_err(|e| DriveHttpError {
            status: 0,
            retry_after_ms: None,
            detail: format!("drive body read error: {e}"),
        })?;
        if let Some(r) = range
            && status == 200
        {
            let start = (r.start as usize).min(body.len());
            let end = (r.end as usize).min(body.len());
            return Ok(body.slice(start..end));
        }
        Ok(body)
    }

    /// Queries metadata for a single `fileId`.
    pub async fn head_file(
        &self,
        file_id: &str,
        auth: &str,
    ) -> Result<Option<ObjectMeta>, DriveHttpError> {
        let url = format!(
            "{}/drive/v3/files/{file_id}?fields=id,size",
            self.base_url()
        );
        let resp = self
            .client()
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, auth)
            .send()
            .await
            .map_err(|e| DriveHttpError {
                status: 0,
                retry_after_ms: None,
                detail: format!("drive head error: {e}"),
            })?;
        let status = resp.status().as_u16();
        let retry_after_ms = parse_retry_after_ms(resp.headers());
        if status == 404 {
            return Ok(None);
        }
        if status != 200 {
            let detail = resp.text().await.unwrap_or_default();
            return Err(DriveHttpError {
                status,
                retry_after_ms,
                detail,
            });
        }
        let meta: FileMetaResp = resp.json().await.map_err(|e| DriveHttpError {
            status: 502,
            retry_after_ms: None,
            detail: format!("drive head parse: {e}"),
        })?;
        let size_bytes = meta
            .size
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Ok(Some(ObjectMeta {
            object_id: meta.id,
            size_bytes,
        }))
    }

    /// Deletes a single file created by this app (`DELETE /drive/v3/files/{fileId}`).
    pub async fn delete_file(&self, file_id: &str, auth: &str) -> Result<(), DriveHttpError> {
        let url = format!("{}/drive/v3/files/{file_id}", self.base_url());
        let resp = self
            .client()
            .delete(&url)
            .header(reqwest::header::AUTHORIZATION, auth)
            .send()
            .await
            .map_err(|e| DriveHttpError {
                status: 0,
                retry_after_ms: None,
                detail: format!("drive delete error: {e}"),
            })?;
        let status = resp.status().as_u16();
        let retry_after_ms = parse_retry_after_ms(resp.headers());
        if matches!(status, 200 | 204 | 404) {
            Ok(())
        } else {
            let detail = resp.text().await.unwrap_or_default();
            Err(DriveHttpError {
                status,
                retry_after_ms,
                detail,
            })
        }
    }

    /// Lists one page of app-created bundles (`files.list` + `nextPageToken`) for DR recovery.
    pub async fn list_bundles_page(
        &self,
        page_token: Option<&str>,
        auth: &str,
    ) -> Result<(Vec<DriveBundleEntry>, Option<String>), DriveHttpError> {
        let mut url = format!(
            "{}/drive/v3/files?fields={}&pageSize=1000&q={}",
            self.base_url(),
            percent_encode("nextPageToken,files(id,name,size)"),
            percent_encode("trashed = false"),
        );
        if let Some(tok) = page_token {
            url.push_str("&pageToken=");
            url.push_str(&percent_encode(tok));
        }
        let resp = self
            .client()
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, auth)
            .send()
            .await
            .map_err(|e| DriveHttpError {
                status: 0,
                retry_after_ms: None,
                detail: format!("drive list error: {e}"),
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
        let parsed: FileListResp = resp.json().await.map_err(|e| DriveHttpError {
            status: 502,
            retry_after_ms: None,
            detail: format!("drive list parse: {e}"),
        })?;
        let entries = parsed
            .files
            .into_iter()
            .map(|f| DriveBundleEntry {
                object_id: f.id,
                name: f.name.unwrap_or_default(),
                size_bytes: f
                    .size
                    .as_deref()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0),
            })
            .collect();
        Ok((entries, parsed.next_page_token))
    }
}
