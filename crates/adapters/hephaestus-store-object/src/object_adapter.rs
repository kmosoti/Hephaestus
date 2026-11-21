//! Apache Arrow `object_store` adapter supporting LocalFS (zero-cloud default), S3/R2, GCS, and InMemory.

use bytes::Bytes;
use core::ops::Range;
use hephaestus_store::{BoxFuture, ObjectBackend, ObjectMeta, ObjectRef, StoreError};
use object_store::aws::AmazonS3Builder;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path as ObjectPath;
use object_store::{Error as OsError, ObjectStore, ObjectStoreExt as _, PutPayload};
use std::path::PathBuf;
use std::sync::Arc;

/// Configuration selecting an Apache Arrow `object_store` backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectStoreConfig {
    /// Zero-cloud local filesystem directory store (default).
    LocalFs {
        /// Root directory where bundle objects live.
        root: PathBuf,
        /// Optional key prefix inside `root`.
        prefix: String,
    },
    /// Ephemeral in-memory store for fast unit tests.
    Memory {
        /// Optional key prefix.
        prefix: String,
    },
    /// Amazon S3 or S3-compatible store (e.g., Cloudflare R2 via custom endpoint).
    S3 {
        /// Bucket name.
        bucket: String,
        /// Optional custom endpoint URL (e.g., R2 or MinIO IPv6 endpoint).
        endpoint: Option<String>,
        /// Optional region name.
        region: Option<String>,
        /// Key prefix inside the bucket.
        prefix: String,
        /// Allow plain HTTP for local testing.
        allow_http: bool,
    },
    /// Google Cloud Storage bucket store.
    Gcs {
        /// GCS bucket name.
        bucket: String,
        /// Key prefix inside the bucket.
        prefix: String,
    },
}

impl ObjectStoreConfig {
    /// Parses a backend URI (`memory://`, `file:///path`, `s3://bucket/prefix`, `gs://bucket/prefix`).
    pub fn from_uri(uri: &str) -> Result<Self, StoreError> {
        if let Some(rest) = uri.strip_prefix("memory://") {
            return Ok(Self::Memory {
                prefix: rest.trim_matches('/').to_owned(),
            });
        }
        if let Some(path) = uri.strip_prefix("file://") {
            if path.is_empty() {
                return Err(StoreError::InvalidInput("file:// URI missing path".into()));
            }
            return Ok(Self::LocalFs {
                root: PathBuf::from(path),
                prefix: String::new(),
            });
        }
        if let Some(rest) = uri.strip_prefix("s3://") {
            let (bucket, prefix) = split_bucket_prefix(rest)?;
            return Ok(Self::S3 {
                bucket,
                endpoint: None,
                region: None,
                prefix,
                allow_http: false,
            });
        }
        if let Some(rest) = uri.strip_prefix("gs://") {
            let (bucket, prefix) = split_bucket_prefix(rest)?;
            return Ok(Self::Gcs { bucket, prefix });
        }
        Err(StoreError::InvalidInput(format!(
            "unsupported object store URI scheme `{uri}` (expected file://, s3://, gs://, or memory://)"
        )))
    }
}

fn split_bucket_prefix(rest: &str) -> Result<(String, String), StoreError> {
    let trimmed = rest.trim_start_matches('/');
    let (bucket, prefix) = match trimmed.split_once('/') {
        Some((b, p)) => (b, p.trim_matches('/')),
        None => (trimmed, ""),
    };
    if bucket.is_empty() {
        return Err(StoreError::InvalidInput(
            "object URI missing bucket name".into(),
        ));
    }
    Ok((bucket.to_owned(), prefix.to_owned()))
}

fn map_os_err(err: OsError) -> StoreError {
    match err {
        OsError::NotFound { path, .. } => StoreError::NotFound(path),
        other => StoreError::Backend(format!("object_store error: {other}")),
    }
}

/// Adapter bridging Apache Arrow [`ObjectStore`] to [`hephaestus_store::ObjectBackend`].
#[derive(Clone)]
pub struct ObjectStoreBackend {
    kind: &'static str,
    prefix: String,
    inner: Arc<dyn ObjectStore>,
}

impl ObjectStoreBackend {
    /// Constructs an [`ObjectStoreBackend`] from [`ObjectStoreConfig`].
    pub fn from_config(cfg: &ObjectStoreConfig) -> Result<Self, StoreError> {
        match cfg {
            ObjectStoreConfig::LocalFs { root, prefix } => {
                std::fs::create_dir_all(root).map_err(|e| {
                    StoreError::Backend(format!("create object root {}: {e}", root.display()))
                })?;
                let fs = LocalFileSystem::new_with_prefix(root).map_err(map_os_err)?;
                Ok(Self {
                    kind: "localfs",
                    prefix: prefix.trim_matches('/').to_owned(),
                    inner: Arc::new(fs),
                })
            }
            ObjectStoreConfig::Memory { prefix } => Ok(Self {
                kind: "memory",
                prefix: prefix.trim_matches('/').to_owned(),
                inner: Arc::new(InMemory::new()),
            }),
            ObjectStoreConfig::S3 {
                bucket,
                endpoint,
                region,
                prefix,
                allow_http,
            } => {
                let mut builder = AmazonS3Builder::from_env()
                    .with_bucket_name(bucket)
                    .with_allow_http(*allow_http);
                if let Some(ep) = endpoint {
                    builder = builder.with_endpoint(ep);
                }
                if let Some(reg) = region {
                    builder = builder.with_region(reg);
                }
                let store = builder.build().map_err(map_os_err)?;
                Ok(Self {
                    kind: "s3",
                    prefix: prefix.trim_matches('/').to_owned(),
                    inner: Arc::new(store),
                })
            }
            ObjectStoreConfig::Gcs { bucket, prefix } => {
                let store = GoogleCloudStorageBuilder::from_env()
                    .with_bucket_name(bucket)
                    .build()
                    .map_err(map_os_err)?;
                Ok(Self {
                    kind: "gcs",
                    prefix: prefix.trim_matches('/').to_owned(),
                    inner: Arc::new(store),
                })
            }
        }
    }

    /// Wraps any existing [`ObjectStore`] instance under an explicit kind label and prefix.
    #[must_use]
    pub fn wrap(
        kind: &'static str,
        prefix: impl Into<String>,
        inner: Arc<dyn ObjectStore>,
    ) -> Self {
        Self {
            kind,
            prefix: prefix.into().trim_matches('/').to_owned(),
            inner,
        }
    }

    fn resolve_path(&self, key: &str) -> Result<ObjectPath, StoreError> {
        let clean = key.trim_start_matches('/');
        let full = if self.prefix.is_empty() || clean.starts_with(&format!("{}/", self.prefix)) {
            clean.to_owned()
        } else {
            format!("{}/{clean}", self.prefix)
        };
        ObjectPath::parse(full)
            .map_err(|e| StoreError::InvalidInput(format!("invalid object path: {e}")))
    }
}

impl ObjectBackend for ObjectStoreBackend {
    fn backend_kind(&self) -> &'static str {
        self.kind
    }

    fn put_bundle<'a>(
        &'a self,
        bundle_key: &'a str,
        bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<ObjectRef, StoreError>> {
        Box::pin(async move {
            let size_bytes = bytes.len() as u64;
            let path = self.resolve_path(bundle_key)?;
            let res = self
                .inner
                .put(&path, PutPayload::from_bytes(Bytes::from(bytes)))
                .await
                .map_err(map_os_err)?;
            Ok(ObjectRef {
                object_id: path.to_string(),
                size_bytes,
                etag: res.e_tag,
            })
        })
    }

    fn get_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StoreError>> {
        Box::pin(async move {
            let path = self.resolve_path(object_id)?;
            let got = self.inner.get(&path).await.map_err(map_os_err)?;
            let bytes = got.bytes().await.map_err(map_os_err)?;
            Ok(bytes.to_vec())
        })
    }

    fn get_range<'a>(
        &'a self,
        object_id: &'a str,
        range: Range<u64>,
    ) -> BoxFuture<'a, Result<Bytes, StoreError>> {
        Box::pin(async move {
            if range.start >= range.end {
                return Ok(Bytes::new());
            }
            let path = self.resolve_path(object_id)?;
            self.inner.get_range(&path, range).await.map_err(map_os_err)
        })
    }

    fn head_bundle<'a>(
        &'a self,
        object_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<ObjectMeta>, StoreError>> {
        Box::pin(async move {
            let path = self.resolve_path(object_id)?;
            match self.inner.head(&path).await {
                Ok(meta) => Ok(Some(ObjectMeta {
                    object_id: meta.location.to_string(),
                    size_bytes: meta.size,
                })),
                Err(OsError::NotFound { .. }) => Ok(None),
                Err(err) => Err(map_os_err(err)),
            }
        })
    }

    fn delete_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let path = self.resolve_path(object_id)?;
            self.inner.delete(&path).await.map_err(map_os_err)
        })
    }
}
