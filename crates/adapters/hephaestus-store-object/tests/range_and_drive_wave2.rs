#![forbid(unsafe_code)]
//! Wave 2 test verifying `PackedCasEngine::get_blob` issues bounded `GRNB0002` range reads
//! fetching far fewer bytes than the full bundle size.

use bytes::Bytes;
use core::ops::Range;
use hephaestus_core::{BlobDigest, IdempotencyKey, RepoId, SealedBundle};
use hephaestus_store::{
    BlobLocation, BoxFuture, CatalogStats, CatalogStore, CommitRef, IdempotentReceipt,
    ObjectBackend, ObjectMeta, ObjectRef, StoreError,
};
use hephaestus_store_object::{ObjectStoreBackend, ObjectStoreConfig, PackedCasEngine};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

type PackedEntry = (String, String, u64, u32);

#[derive(Default)]
struct MemCatalog {
    inline: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    packed: Mutex<HashMap<[u8; 32], PackedEntry>>,
}

impl CatalogStore for MemCatalog {
    fn put_inline<'a>(
        &'a self,
        d: &'a BlobDigest,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.inline.lock().unwrap().insert(d.0, data.to_vec());
            Ok(())
        })
    }
    fn contains_blob<'a>(&'a self, d: &'a BlobDigest) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            Ok(self.inline.lock().unwrap().contains_key(&d.0)
                || self.packed.lock().unwrap().contains_key(&d.0))
        })
    }
    fn lookup_blob<'a>(
        &'a self,
        d: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<Option<BlobLocation>, StoreError>> {
        Box::pin(async move {
            if let Some(b) = self.inline.lock().unwrap().get(&d.0).cloned() {
                return Ok(Some(BlobLocation::Inline(b)));
            }
            Ok(self.packed.lock().unwrap().get(&d.0).cloned().map(
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
        b: &'a SealedBundle,
        oid: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut p = self.packed.lock().unwrap();
            for e in &b.entries {
                p.insert(
                    e.blake3_hash,
                    (
                        oid.to_owned(),
                        b.bundle_id.clone(),
                        e.byte_offset,
                        e.byte_len,
                    ),
                );
            }
            Ok(())
        })
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

struct CountingObjectBackend {
    inner: Arc<dyn ObjectBackend>,
    full_get_calls: AtomicUsize,
    range_bytes_fetched: AtomicU64,
}

impl ObjectBackend for CountingObjectBackend {
    fn backend_kind(&self) -> &'static str {
        self.inner.backend_kind()
    }
    fn put_bundle<'a>(
        &'a self,
        key: &'a str,
        bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<ObjectRef, StoreError>> {
        self.inner.put_bundle(key, bytes)
    }
    fn get_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StoreError>> {
        self.full_get_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_bundle(object_id)
    }
    fn get_range<'a>(
        &'a self,
        object_id: &'a str,
        range: Range<u64>,
    ) -> BoxFuture<'a, Result<Bytes, StoreError>> {
        Box::pin(async move {
            let bytes = self.inner.get_range(object_id, range).await?;
            self.range_bytes_fetched
                .fetch_add(bytes.len() as u64, Ordering::SeqCst);
            Ok(bytes)
        })
    }
    fn head_bundle<'a>(
        &'a self,
        object_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<ObjectMeta>, StoreError>> {
        self.inner.head_bundle(object_id)
    }
    fn delete_bundle<'a>(&'a self, object_id: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        self.inner.delete_bundle(object_id)
    }
}

fn prng_blob(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        out.push((s >> 33) as u8);
    }
    out
}

#[tokio::test]
async fn packed_cas_range_reads_fetch_far_fewer_bytes_than_full_bundle() {
    let mem = Arc::new(
        ObjectStoreBackend::from_config(&ObjectStoreConfig::Memory {
            prefix: String::new(),
        })
        .unwrap(),
    );
    let counting = Arc::new(CountingObjectBackend {
        inner: mem,
        full_get_calls: AtomicUsize::new(0),
        range_bytes_fetched: AtomicU64::new(0),
    });
    let catalog = Arc::new(MemCatalog::default());
    let cas = PackedCasEngine::new(catalog, counting.clone(), 8 * 1024 * 1024);

    let mut blobs = Vec::new();
    for i in 0u64..32 {
        let data = prng_blob(64 * 1024, i + 100);
        let h = cas.put_blob(data.clone(), true).await.unwrap();
        blobs.push((h, data));
    }
    let obj_id = cas.flush_bundle().await.unwrap().expect("sealed bundle");
    let total_size = counting
        .head_bundle(&obj_id)
        .await
        .unwrap()
        .unwrap()
        .size_bytes;
    assert!(
        total_size > 1_500_000,
        "expected >1.5 MiB bundle, got {total_size}"
    );

    let (target_h, target_bytes) = &blobs[21];
    let got = cas.get_blob(target_h).await.unwrap().unwrap();
    assert_eq!(&got, target_bytes);
    assert_eq!(counting.full_get_calls.load(Ordering::SeqCst), 0);
    let fetched = counting.range_bytes_fetched.load(Ordering::SeqCst);
    assert!(
        fetched * 4 < total_size,
        "expected range read ({fetched}B) << total bundle ({total_size}B)"
    );
}
