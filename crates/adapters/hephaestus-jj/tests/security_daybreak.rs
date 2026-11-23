#![forbid(unsafe_code)]
//! Security regression test for Daybreak finding #5 in `hephaestus-jj`:
//! single-pass changed-OID indexing avoids multiplicative blob materialization across bookmarks.

use hephaestus_core::{BlobDigest, RepoId};
use hephaestus_jj::{JjCommitInput, JjRepoService};
use hephaestus_store::{
    BlobLocation, BoxFuture, CatalogStats, CatalogStore, CommitRef, IdempotentReceipt, StoreError,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct CountingCatalog {
    blobs: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    refs: Mutex<HashMap<String, CommitRef>>,
}

impl CatalogStore for CountingCatalog {
    fn put_inline<'a>(
        &'a self,
        d: &'a BlobDigest,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        self.blobs.lock().unwrap().insert(d.0, data.to_vec());
        Box::pin(async { Ok(()) })
    }
    fn contains_blob<'a>(&'a self, d: &'a BlobDigest) -> BoxFuture<'a, Result<bool, StoreError>> {
        let has = self.blobs.lock().unwrap().contains_key(&d.0);
        Box::pin(async move { Ok(has) })
    }
    fn lookup_blob<'a>(
        &'a self,
        d: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<Option<BlobLocation>, StoreError>> {
        let hit = self
            .blobs
            .lock()
            .unwrap()
            .get(&d.0)
            .cloned()
            .map(BlobLocation::Inline);
        Box::pin(async move { Ok(hit) })
    }
    fn record_bundle<'a>(
        &'a self,
        _: &'a hephaestus_core::SealedBundle,
        _: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn check_idempotent<'a>(
        &'a self,
        _: &'a hephaestus_core::IdempotencyKey,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async { Ok(None) })
    }
    fn record_idempotent<'a>(
        &'a self,
        _: &'a hephaestus_core::IdempotencyKey,
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
    fn upsert_ref<'a>(&'a self, cref: &'a CommitRef) -> BoxFuture<'a, Result<(), StoreError>> {
        self.refs
            .lock()
            .unwrap()
            .insert(cref.bookmark.clone(), cref.clone());
        Box::pin(async { Ok(()) })
    }
    fn list_refs<'a>(&'a self, _: &'a RepoId) -> BoxFuture<'a, Result<Vec<CommitRef>, StoreError>> {
        let out = self.refs.lock().unwrap().values().cloned().collect();
        Box::pin(async move { Ok(out) })
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

#[tokio::test]
async fn shared_blobs_across_many_bookmarks_are_indexed_once_and_unchanged_bookmarks_skipped() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hep-jjsec-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let svc = JjRepoService::new("Sec Bot", "sec@example.invalid").unwrap();
    svc.init_hephaestus_repo(&dir).await.unwrap();

    let large_payload = vec![0x4Du8; 512 * 1024];
    let mut files = BTreeMap::new();
    files.insert("shared.bin".into(), large_payload);
    for i in 0..25 {
        svc.commit_files_and_bookmark(
            &dir,
            &JjCommitInput {
                bookmark: format!("bm-{i:02}"),
                description: format!("bookmark {i}"),
                files: files.clone(),
            },
        )
        .await
        .unwrap();
    }

    let catalog = CountingCatalog::default();
    let repo_id = RepoId::parse("sec/multi-bm").unwrap();
    let large_puts = AtomicUsize::new(0);
    let refs = svc
        .index_bookmarks_into_catalog(&dir, &repo_id, &catalog, |bytes| {
            let is_large = bytes.len() == 512 * 1024;
            let count_ref = &large_puts;
            let cat = &catalog;
            async move {
                if is_large {
                    count_ref.fetch_add(1, Ordering::SeqCst);
                }
                let d = BlobDigest::of(&bytes);
                cat.put_inline(&d, &bytes).await?;
                Ok(d)
            }
        })
        .await
        .unwrap();
    assert_eq!(refs.len(), 25);
    assert_eq!(
        large_puts.load(Ordering::SeqCst),
        1,
        "shared FileId across 25 bookmarks must only be read/indexed once"
    );

    // Second pass with no bookmark changes skips all 25 bookmarks.
    let second = svc
        .index_bookmarks_into_catalog(&dir, &repo_id, &catalog, |bytes| async move {
            Ok(BlobDigest::of(&bytes))
        })
        .await
        .unwrap();
    assert!(second.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
