#![forbid(unsafe_code)]
//! Integration and deterministic simulation tests for `object_store` (LocalFS/S3/GCS configs)
//! and native-IPv6 `GoogleDriveStore` HTTP 429 retry resilience.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use hephaestus_core::{BlobDigest, IdempotencyKey, RepoId, SealedBundle, SecretString};
use hephaestus_store::{
    BlobLocation, BoxFuture, CatalogStats, CatalogStore, CommitRef, IdempotentReceipt,
    ObjectBackend, StoreError,
};
use hephaestus_store_object::{
    DriveHttpClient, GoogleDriveStore, ObjectStoreBackend, ObjectStoreConfig, PackedCasEngine,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

type PackedEntry = (String, String, u64, u32);

#[derive(Default)]
struct MemCatalog {
    inline: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    packed: Mutex<HashMap<[u8; 32], PackedEntry>>,
    bundles: Mutex<usize>,
}

impl CatalogStore for MemCatalog {
    fn put_inline<'a>(
        &'a self,
        digest: &'a BlobDigest,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.inline
                .lock()
                .unwrap()
                .entry(digest.0)
                .or_insert_with(|| data.to_vec());
            Ok(())
        })
    }

    fn contains_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            Ok(self.inline.lock().unwrap().contains_key(&digest.0)
                || self.packed.lock().unwrap().contains_key(&digest.0))
        })
    }

    fn lookup_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<Option<BlobLocation>, StoreError>> {
        Box::pin(async move {
            if let Some(bytes) = self.inline.lock().unwrap().get(&digest.0).cloned() {
                return Ok(Some(BlobLocation::Inline(bytes)));
            }
            Ok(self.packed.lock().unwrap().get(&digest.0).cloned().map(
                |(object_id, bundle_id, byte_offset, byte_len)| BlobLocation::Packed {
                    object_id,
                    bundle_id,
                    byte_offset,
                    byte_len,
                },
            ))
        })
    }

    fn record_bundle<'a>(
        &'a self,
        bundle: &'a SealedBundle,
        object_id: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            *self.bundles.lock().unwrap() += 1;
            let mut p = self.packed.lock().unwrap();
            for entry in &bundle.entries {
                p.entry(entry.blake3_hash).or_insert_with(|| {
                    (
                        object_id.to_owned(),
                        bundle.bundle_id.clone(),
                        entry.byte_offset,
                        entry.byte_len,
                    )
                });
            }
            Ok(())
        })
    }

    fn check_idempotent<'a>(
        &'a self,
        _key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async { Ok(None) })
    }

    fn record_idempotent<'a>(
        &'a self,
        _key: &'a IdempotencyKey,
        ack_payload: &'a [u8],
        _now_ms: u64,
    ) -> BoxFuture<'a, Result<IdempotentReceipt, StoreError>> {
        Box::pin(async move {
            Ok(IdempotentReceipt {
                already_applied: false,
                ack_payload: ack_payload.to_vec(),
            })
        })
    }

    fn upsert_ref<'a>(
        &'a self,
        _commit_ref: &'a CommitRef,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn list_refs<'a>(
        &'a self,
        _repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<Vec<CommitRef>, StoreError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn stats(&self) -> BoxFuture<'_, Result<CatalogStats, StoreError>> {
        Box::pin(async move {
            Ok(CatalogStats {
                inline_count: self.inline.lock().unwrap().len() as u64,
                packed_count: self.packed.lock().unwrap().len() as u64,
                bundle_count: *self.bundles.lock().unwrap() as u64,
                idempotency_count: 0,
                decision_count: 0,
                observation_count: 0,
            })
        })
    }

    fn checkpoint_wal(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn export_ltx_snapshot_zstd(&self) -> BoxFuture<'_, Result<Vec<u8>, StoreError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct MockDrive {
    files: Mutex<HashMap<String, Vec<u8>>>,
    next_id: AtomicUsize,
    remaining_429s: AtomicUsize,
    uploads: AtomicUsize,
    list_calls: AtomicUsize,
}

async fn start_mock_drive(inject_429s: usize) -> (String, Arc<MockDrive>) {
    let state = Arc::new(MockDrive {
        files: Mutex::new(HashMap::new()),
        next_id: AtomicUsize::new(1),
        remaining_429s: AtomicUsize::new(inject_429s),
        uploads: AtomicUsize::new(0),
        list_calls: AtomicUsize::new(0),
    });

    let app = Router::new()
        .route(
            "/upload/drive/v3/files",
            post(|State(st): State<Arc<MockDrive>>| async move {
                let prev = st.remaining_429s.try_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    v.checked_sub(1)
                });
                if prev.is_ok() {
                    return (StatusCode::TOO_MANY_REQUESTS, HeaderMap::new(), "rate limited".to_owned());
                }
                let sid = st.next_id.fetch_add(1, Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert("location", format!("/upload/session/{sid}").parse().unwrap());
                (StatusCode::OK, headers, String::new())
            }),
        )
        .route(
            "/upload/session/{sid}",
            put(|Path(sid): Path<String>, State(st): State<Arc<MockDrive>>, body: Bytes| async move {
                let file_id = format!("gd-file-{sid}");
                st.files.lock().unwrap().insert(file_id.clone(), body.to_vec());
                st.uploads.fetch_add(1, Ordering::SeqCst);
                (StatusCode::OK, Json(json!({ "id": file_id })))
            }),
        )
        .route(
            "/drive/v3/files/{file_id}",
            get(
                |Path(file_id): Path<String>,
                 headers: HeaderMap,
                 State(st): State<Arc<MockDrive>>| async move {
                    let Some(bytes) = st.files.lock().unwrap().get(&file_id).cloned() else {
                        return (StatusCode::NOT_FOUND, Vec::new());
                    };
                    if let Some(r) = headers.get("range").and_then(|v| v.to_str().ok())
                        && let Some(spec) = r.strip_prefix("bytes=")
                        && let Some((a, b)) = spec.split_once('-')
                        && let (Ok(start), Ok(end_inc)) = (a.parse::<usize>(), b.parse::<usize>())
                    {
                        let s = start.min(bytes.len());
                        let e = (end_inc + 1).min(bytes.len());
                        return (StatusCode::PARTIAL_CONTENT, bytes[s..e].to_vec());
                    }
                    (StatusCode::OK, bytes)
                },
            ),
        )
        .route(
            "/drive/v3/files",
            get(|State(st): State<Arc<MockDrive>>| async move {
                st.list_calls.fetch_add(1, Ordering::SeqCst);
                (StatusCode::FORBIDDEN, "files.list forbidden")
            }),
        )
        .with_state(Arc::clone(&state));

    let listener = TcpListener::bind("[::1]:0")
        .await
        .expect("bind IPv6 loopback");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://[{}]:{}", addr.ip(), addr.port()), state)
}

#[tokio::test]
async fn localfs_zero_cloud_object_store_and_uri_parsing_round_trip() {
    let tmp = std::env::temp_dir().join(format!("hep-localfs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let uri = format!("file://{}", tmp.display());
    let cfg = ObjectStoreConfig::from_uri(&uri).unwrap();
    let backend = Arc::new(ObjectStoreBackend::from_config(&cfg).unwrap());
    assert_eq!(backend.backend_kind(), "localfs");

    let catalog = Arc::new(MemCatalog::default());
    let cas = PackedCasEngine::new(catalog, backend.clone(), 4 * 1024 * 1024);

    let tiny = b"tiny-inline-manifest".to_vec();
    let tiny_h = cas.put_blob(tiny.clone(), false).await.unwrap();
    let big = vec![0x42u8; 16 * 1024];
    let big_h = cas.put_blob(big.clone(), false).await.unwrap();
    let obj_id = cas
        .flush_bundle()
        .await
        .unwrap()
        .expect("one flushed bundle");
    assert!(backend.head_bundle(&obj_id).await.unwrap().is_some());

    assert_eq!(cas.get_blob(&tiny_h).await.unwrap(), Some(tiny));
    assert_eq!(cas.get_blob(&big_h).await.unwrap(), Some(big));

    // Verify S3/GCS URI parsing constructs configs cleanly.
    assert!(matches!(
        ObjectStoreConfig::from_uri("s3://example-bucket/hephaestus").unwrap(),
        ObjectStoreConfig::S3 { .. }
    ));
    assert!(matches!(
        ObjectStoreConfig::from_uri("gs://example-bucket/hephaestus").unwrap(),
        ObjectStoreConfig::Gcs { .. }
    ));
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn google_drive_store_ipv6_survives_429_and_packs_10k_blobs_in_one_bundle() {
    let (base_url, mock) = start_mock_drive(3).await;
    let http = DriveHttpClient::new(&base_url, SecretString::new("test-token")).unwrap();
    let drive = Arc::new(GoogleDriveStore::new(http, 42).with_fast_test_retries());
    assert_eq!(drive.backend_kind(), "google-drive");

    let catalog = Arc::new(MemCatalog::default());
    let cas = PackedCasEngine::new(catalog, drive, 8 * 1024 * 1024);

    let mut samples = Vec::new();
    for i in 0u32..10_000 {
        let payload = format!("drive-blob-{i:05}-{}", i * 17).into_bytes();
        let h = cas.put_blob(payload.clone(), true).await.unwrap();
        if matches!(i, 0 | 77 | 5000 | 9999) {
            samples.push((h, payload));
        }
    }
    let file_id = cas.flush_bundle().await.unwrap().expect("one bundle");
    assert_eq!(file_id, "gd-file-1");
    assert_eq!(mock.uploads.load(Ordering::SeqCst), 1);
    assert_eq!(mock.list_calls.load(Ordering::SeqCst), 0);

    for (h, expected) in samples {
        assert_eq!(cas.get_blob(&h).await.unwrap(), Some(expected));
    }
    assert_eq!(mock.list_calls.load(Ordering::SeqCst), 0);
}
