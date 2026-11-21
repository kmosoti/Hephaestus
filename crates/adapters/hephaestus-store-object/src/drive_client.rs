//! Quota-governed 20 TB Google Drive v3 (`drive.file`) [`ObjectBackend`] with retries,
//! OAuth refresh recovery, `Retry-After` backoff, and paginated DR `list_bundles`.

use crate::drive_http::DriveHttpClient;
use crate::drive_ops::{DriveBundleEntry, DriveHttpError};
use bytes::Bytes;
use core::future::Future;
use core::ops::Range;
use hephaestus_core::{DriveOpKind, DriveQuotaGovernor, MonoTime, QuotaDecision};
use hephaestus_store::{BoxFuture, ObjectBackend, ObjectMeta, ObjectRef, StoreError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_ATTEMPTS: usize = 8;

/// Quota-governed 20 TB Google Drive `drive.file` adapter implementing [`ObjectBackend`].
pub struct GoogleDriveStore {
    http: DriveHttpClient,
    governor: Mutex<DriveQuotaGovernor>,
    boot: Instant,
    virtual_advance_ms: AtomicU64,
    fast_retry_for_tests: bool,
}

impl GoogleDriveStore {
    /// Creates a Drive object backend governed by [`DriveQuotaGovernor`].
    #[must_use]
    pub fn new(http: DriveHttpClient, jitter_seed: u64) -> Self {
        Self {
            http,
            governor: Mutex::new(DriveQuotaGovernor::new(MonoTime(0), jitter_seed)),
            boot: Instant::now(),
            virtual_advance_ms: AtomicU64::new(0),
            fast_retry_for_tests: false,
        }
    }

    /// Accelerates retry sleeps for deterministic simulation tests.
    #[must_use]
    pub fn with_fast_test_retries(mut self) -> Self {
        self.fast_retry_for_tests = true;
        self
    }

    /// Explicitly enumerates all Drive bundles via paginated `files.list` for DR recovery.
    pub async fn list_bundles(&self) -> Result<Vec<DriveBundleEntry>, StoreError> {
        let mut all = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let tok_clone = next_token.clone();
            let (page, next) = self
                .with_retry(DriveOpKind::FilesGet, 0, |auth| {
                    let tok = tok_clone.clone();
                    async move { self.http.list_bundles_page(tok.as_deref(), &auth).await }
                })
                .await?;
            all.extend(page);
            match next {
                Some(tok) if !tok.is_empty() => next_token = Some(tok),
                _ => return Ok(all),
            }
        }
    }

    fn now_mono(&self) -> MonoTime {
        let wall = self.boot.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        MonoTime(wall.saturating_add(self.virtual_advance_ms.load(Ordering::Relaxed)))
    }

    async fn sleep_until_mono(&self, target: MonoTime) {
        let wait = target.saturating_sub(self.now_mono());
        if wait == 0 {
            return;
        }
        if self.fast_retry_for_tests {
            tokio::time::sleep(Duration::from_millis(wait.min(5))).await;
            self.virtual_advance_ms.fetch_add(wait, Ordering::Relaxed);
        } else {
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
    }

    async fn wait_for_quota(&self, op: DriveOpKind, upload_bytes: u64) -> Result<(), StoreError> {
        loop {
            let decision = {
                let now = self.now_mono();
                self.governor
                    .lock()
                    .await
                    .check_and_consume(op, upload_bytes, now)
            };
            match decision {
                QuotaDecision::Allow => return Ok(()),
                QuotaDecision::WaitUntil(until) => self.sleep_until_mono(until).await,
                QuotaDecision::DailyCapExceeded => {
                    return Err(StoreError::RateLimited(
                        "Drive daily 750 GiB transfer cap exceeded".into(),
                    ));
                }
            }
        }
    }

    async fn with_retry<T, F, Fut>(
        &self,
        op: DriveOpKind,
        upload_bytes: u64,
        mut call: F,
    ) -> Result<T, StoreError>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = Result<T, DriveHttpError>>,
    {
        let mut force_refresh = false;
        let mut last_err: Option<DriveHttpError> = None;
        for attempt in 0..MAX_ATTEMPTS {
            self.wait_for_quota(op, upload_bytes).await?;
            let auth = match self
                .http
                .bearer_header(self.now_mono(), force_refresh)
                .await
            {
                Ok(h) => {
                    force_refresh = false;
                    h
                }
                Err(err) if err.is_retryable() && attempt + 1 < MAX_ATTEMPTS => {
                    let until = self
                        .governor
                        .lock()
                        .await
                        .on_rate_limited(self.now_mono(), err.retry_after_ms);
                    last_err = Some(err);
                    self.sleep_until_mono(until).await;
                    continue;
                }
                Err(err) => return Err(err.into_store_error()),
            };

            match call(auth).await {
                Ok(val) => {
                    self.governor.lock().await.on_success();
                    return Ok(val);
                }
                Err(err) if err.status == 401 && attempt + 1 < MAX_ATTEMPTS => {
                    force_refresh = true;
                    last_err = Some(err);
                }
                Err(err) if err.is_retryable() && attempt + 1 < MAX_ATTEMPTS => {
                    let until = self
                        .governor
                        .lock()
                        .await
                        .on_rate_limited(self.now_mono(), err.retry_after_ms);
                    last_err = Some(err);
                    self.sleep_until_mono(until).await;
                }
                Err(err) => return Err(err.into_store_error()),
            }
        }
        Err(last_err.map_or_else(
            || StoreError::RateLimited(format!("Drive op failed after {MAX_ATTEMPTS} attempts")),
            DriveHttpError::into_store_error,
        ))
    }
}

impl ObjectBackend for GoogleDriveStore {
    fn backend_kind(&self) -> &'static str {
        "google-drive"
    }

    fn put_bundle<'a>(
        &'a self,
        bundle_key: &'a str,
        bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<ObjectRef, StoreError>> {
        Box::pin(async move {
            let size = bytes.len() as u64;
            let file_id = self
                .with_retry(DriveOpKind::FilesCreate, size, |auth| {
                    let payload = bytes.as_slice();
                    async move { self.http.upload_resumable(bundle_key, payload, &auth).await }
                })
                .await?;
            Ok(ObjectRef {
                object_id: file_id,
                size_bytes: size,
                etag: None,
            })
        })
    }

    fn get_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StoreError>> {
        Box::pin(async move {
            let bytes = self
                .with_retry(DriveOpKind::FilesDownload, 0, |auth| async move {
                    self.http.download_bytes(object_id, None, &auth).await
                })
                .await?;
            Ok(bytes.to_vec())
        })
    }

    fn get_range<'a>(
        &'a self,
        object_id: &'a str,
        range: Range<u64>,
    ) -> BoxFuture<'a, Result<Bytes, StoreError>> {
        Box::pin(async move {
            self.with_retry(DriveOpKind::FilesDownload, 0, |auth| {
                let r = range.clone();
                async move { self.http.download_bytes(object_id, Some(r), &auth).await }
            })
            .await
        })
    }

    fn head_bundle<'a>(
        &'a self,
        object_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<ObjectMeta>, StoreError>> {
        Box::pin(async move {
            self.with_retry(DriveOpKind::FilesGet, 0, |auth| async move {
                self.http.head_file(object_id, &auth).await
            })
            .await
        })
    }

    fn delete_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.with_retry(DriveOpKind::FilesGet, 0, |auth| async move {
                self.http.delete_file(object_id, &auth).await
            })
            .await
        })
    }
}
