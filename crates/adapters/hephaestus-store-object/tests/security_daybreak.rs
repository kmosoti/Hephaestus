#![forbid(unsafe_code)]
//! Security regression tests for Daybreak findings #12, #13, and #15 in `hephaestus-store-object`.

use bytes::Bytes;
use core::ops::Range;
use hephaestus_core::{
    BUNDLE_MAGIC_V1, BUNDLE_MAGIC_V2, BlobDigest, BundleError, IdempotencyKey, MAX_BUNDLE_FRAMES,
    MAX_LEGACY_V1_DECODED_BYTES, RepoId, SealedBundle,
};
use hephaestus_store::{
    BlobLocation, BoxFuture, CatalogStats, CatalogStore, CommitRef, IdempotentReceipt,
    ObjectBackend, ObjectMeta, ObjectRef, StoreError,
};
use hephaestus_store_object::{DriveHttpError, PackedCasEngine};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct StubCatalog {
    object_id: String,
    digest: BlobDigest,
}

impl CatalogStore for StubCatalog {
    fn put_inline<'a>(
        &'a self,
        _: &'a BlobDigest,
        _: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn contains_blob<'a>(&'a self, _: &'a BlobDigest) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async { Ok(false) })
    }
    fn lookup_blob<'a>(
        &'a self,
        d: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<Option<BlobLocation>, StoreError>> {
        let oid = self.object_id.clone();
        let match_d = *d == self.digest;
        Box::pin(async move {
            Ok(match_d.then_some(BlobLocation::Packed {
                object_id: oid,
                bundle_id: "b".into(),
                byte_offset: 0,
                byte_len: 16,
            }))
        })
    }
    fn record_bundle<'a>(
        &'a self,
        _: &'a SealedBundle,
        _: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn check_idempotent<'a>(
        &'a self,
        _: &'a IdempotencyKey,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async { Ok(None) })
    }
    fn record_idempotent<'a>(
        &'a self,
        _: &'a IdempotencyKey,
        ack: &'a [u8],
        _: u64,
    ) -> BoxFuture<'a, Result<IdempotentReceipt, StoreError>> {
        Box::pin(async move {
            Ok(IdempotentReceipt {
                already_applied: false,
                ack_payload: ack.to_vec(),
            })
        })
    }
    fn upsert_ref<'a>(&'a self, _: &'a CommitRef) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn list_refs<'a>(&'a self, _: &'a RepoId) -> BoxFuture<'a, Result<Vec<CommitRef>, StoreError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn stats(&self) -> BoxFuture<'_, Result<CatalogStats, StoreError>> {
        Box::pin(async { Ok(CatalogStats::default()) })
    }
    fn checkpoint_wal(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn export_ltx_snapshot_zstd(&self) -> BoxFuture<'_, Result<Vec<u8>, StoreError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct MockMaliciousObjects {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    range_calls: AtomicUsize,
}

impl ObjectBackend for MockMaliciousObjects {
    fn backend_kind(&self) -> &'static str {
        "mock"
    }
    fn put_bundle<'a>(
        &'a self,
        key: &'a str,
        bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<ObjectRef, StoreError>> {
        let len = bytes.len() as u64;
        self.blobs.lock().unwrap().insert(key.to_owned(), bytes);
        Box::pin(async move {
            Ok(ObjectRef {
                object_id: key.to_owned(),
                size_bytes: len,
                etag: None,
            })
        })
    }
    fn get_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StoreError>> {
        let res = self
            .blobs
            .lock()
            .unwrap()
            .get(object_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound("missing".into()));
        Box::pin(async move { res })
    }
    fn get_range<'a>(
        &'a self,
        object_id: &'a str,
        range: Range<u64>,
    ) -> BoxFuture<'a, Result<Bytes, StoreError>> {
        self.range_calls.fetch_add(1, Ordering::SeqCst);
        let res = self
            .blobs
            .lock()
            .unwrap()
            .get(object_id)
            .map(|b| {
                let s = (range.start as usize).min(b.len());
                let e = (range.end as usize).min(b.len());
                Bytes::copy_from_slice(&b[s..e])
            })
            .ok_or_else(|| StoreError::NotFound("missing".into()));
        Box::pin(async move { res })
    }
    fn head_bundle<'a>(
        &'a self,
        object_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<ObjectMeta>, StoreError>> {
        let meta = self
            .blobs
            .lock()
            .unwrap()
            .get(object_id)
            .map(|b| ObjectMeta {
                object_id: object_id.to_owned(),
                size_bytes: b.len() as u64,
            });
        Box::pin(async move { Ok(meta) })
    }
    fn delete_bundle<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn packed_cas_rejects_oversized_grnb0002_directory_and_legacy_grnb0001_bomb() {
    let digest = BlobDigest::of(b"target");
    let objects = Arc::new(MockMaliciousObjects {
        blobs: Mutex::new(HashMap::new()),
        range_calls: AtomicUsize::new(0),
    });

    // 1. Oversized GRNB0002 frame_count must fail after the initial 4 KiB probe (no 2nd range read or legacy fallback).
    let mut bad_v2 = Vec::from(*BUNDLE_MAGIC_V2);
    bad_v2.extend_from_slice(&((MAX_BUNDLE_FRAMES as u32) + 5).to_le_bytes());
    bad_v2.extend_from_slice(&[0u8; 64]);
    objects
        .blobs
        .lock()
        .unwrap()
        .insert("bad-v2".into(), bad_v2);

    let cas_v2 = PackedCasEngine::new(
        Arc::new(StubCatalog {
            object_id: "bad-v2".into(),
            digest,
        }),
        objects.clone(),
        1024,
    );
    let err = cas_v2.get_blob(&digest).await.unwrap_err();
    assert!(matches!(
        err,
        StoreError::Bundle(BundleError::InvalidFormat)
    ));
    assert_eq!(objects.range_calls.load(Ordering::SeqCst), 1);

    // 2. Legacy GRNB0001 decompression bomb fails cleanly with bounded memory (~2 KiB Zstd RLE stream -> >64 MiB).
    let mut bomb_zst = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x38]; // Zstd magic, FHD=0, 128 KiB window
    let raw_hdr = (8u32 << 3).to_le_bytes(); // Last=0, Raw=0, len=8
    bomb_zst.extend_from_slice(&raw_hdr[..3]);
    bomb_zst.extend_from_slice(BUNDLE_MAGIC_V1);
    let rle_count = (MAX_LEGACY_V1_DECODED_BYTES / (128 * 1024)) + 2;
    for i in 0..rle_count {
        let last = u32::from(i + 1 == rle_count);
        let blk_hdr = ((131_072u32 << 3) | (1u32 << 1) | last).to_le_bytes();
        bomb_zst.extend_from_slice(&blk_hdr[..3]);
        bomb_zst.push(0x00);
    }
    objects
        .blobs
        .lock()
        .unwrap()
        .insert("bomb-v1".into(), bomb_zst);

    let cas_v1 = PackedCasEngine::new(
        Arc::new(StubCatalog {
            object_id: "bomb-v1".into(),
            digest,
        }),
        objects,
        1024,
    );
    let err_v1 = cas_v1.get_blob(&digest).await.unwrap_err();
    assert!(matches!(
        err_v1,
        StoreError::Bundle(BundleError::InvalidFormat)
    ));
}

#[test]
fn drive_http_error_sanitizes_provider_bodies() {
    let err = DriveHttpError {
        status: 403,
        retry_after_ms: None,
        detail: r#"{"secret_internal":"https://internal/path/secret"}"#.into(),
    };
    let store_err = err.into_store_error();
    let msg = store_err.to_string();
    assert!(!msg.contains("secret_internal"));
    assert!(!msg.contains("https://internal"));
}
