#![forbid(unsafe_code)]
//! Integration tests for `HephaestusBackend`, `JjRepoService`, and `GitSmartHttpBridge`.

use hephaestus_core::{BlobDigest, RepoId};
use hephaestus_jj::{GitSmartHttpBridge, HephaestusBackend, JjCommitInput, JjRepoService};
use hephaestus_store::{
    BlobLocation, BoxFuture, CatalogStats, CatalogStore, CommitRef, IdempotentReceipt, StoreError,
};
use jj_lib::repo::Repo as _;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct InMemIndex {
    blobs: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    refs: Mutex<Vec<CommitRef>>,
}

impl CatalogStore for InMemIndex {
    fn put_inline<'a>(
        &'a self,
        digest: &'a BlobDigest,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.blobs.lock().unwrap().insert(digest.0, data.to_vec());
            Ok(())
        })
    }

    fn contains_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move { Ok(self.blobs.lock().unwrap().contains_key(&digest.0)) })
    }

    fn lookup_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<Option<BlobLocation>, StoreError>> {
        Box::pin(async move {
            Ok(self
                .blobs
                .lock()
                .unwrap()
                .get(&digest.0)
                .cloned()
                .map(BlobLocation::Inline))
        })
    }

    fn record_bundle<'a>(
        &'a self,
        _bundle: &'a hephaestus_core::SealedBundle,
        _object_id: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn check_idempotent<'a>(
        &'a self,
        _key: &'a hephaestus_core::IdempotencyKey,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async { Ok(None) })
    }

    fn record_idempotent<'a>(
        &'a self,
        _key: &'a hephaestus_core::IdempotencyKey,
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
        commit_ref: &'a CommitRef,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.refs.lock().unwrap().push(commit_ref.clone());
            Ok(())
        })
    }

    fn list_refs<'a>(
        &'a self,
        _repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<Vec<CommitRef>, StoreError>> {
        Box::pin(async move { Ok(self.refs.lock().unwrap().clone()) })
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

fn temp_dir(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hep-jj-{name}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn hephaestus_jj_backend_commits_reads_and_indexes_oplog() {
    let dir = temp_dir("backend");
    let svc = JjRepoService::new("Hephaestus Bot", "bot@example.invalid").unwrap();
    let repo = svc.init_hephaestus_repo(&dir).await.unwrap();
    assert_eq!(repo.store().backend().name(), HephaestusBackend::NAME);

    let mut files = BTreeMap::new();
    files.insert("README.md".into(), b"# Hephaestus JJ Test\n".to_vec());
    files.insert(
        "src/lib.rs".into(),
        b"pub fn ok() -> bool { true }\n".to_vec(),
    );

    let res = svc
        .commit_files_and_bookmark(
            &dir,
            &JjCommitInput {
                bookmark: "main".into(),
                description: "initial commit".into(),
                files: files.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(res.files_written, 2);

    let loaded = svc.read_commit_files(&dir, &res.commit_id).await.unwrap();
    assert_eq!(loaded, files);

    let ops = svc.list_op_log(&dir, 10).await.unwrap();
    assert!(!ops.is_empty());
    assert_eq!(ops[0].op_id, res.op_id);

    let catalog = InMemIndex::default();
    let repo_id = RepoId::parse("example/repo").unwrap();
    let indexed = svc
        .index_bookmarks_into_catalog(&dir, &repo_id, &catalog, |bytes| {
            let d = BlobDigest::of(&bytes);
            let cat = &catalog;
            async move {
                cat.put_inline(&d, &bytes).await?;
                Ok(d)
            }
        })
        .await
        .unwrap();
    assert_eq!(indexed.len(), 1);
    assert_eq!(indexed[0].bookmark, "main");
    assert_eq!(indexed[0].commit_id.as_str(), res.commit_id);

    // Verify large multi-chunk FastCDC file round-trip through HephaestusBackend CAS.
    let mut big_file = Vec::with_capacity(200 * 1024);
    let mut seed = 0x5EEDu64;
    for _ in 0..(200 * 1024) {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        big_file.push((seed >> 33) as u8);
    }
    let mut big_map = BTreeMap::new();
    big_map.insert("blobs/large.bin".into(), big_file.clone());
    let big_res = svc
        .commit_files_and_bookmark(
            &dir,
            &JjCommitInput {
                bookmark: "main".into(),
                description: "fastcdc large file commit".into(),
                files: big_map,
            },
        )
        .await
        .unwrap();
    let loaded_big = svc
        .read_commit_files(&dir, &big_res.commit_id)
        .await
        .unwrap();
    assert_eq!(loaded_big.get("blobs/large.bin"), Some(&big_file));
    // Verify CAS directory contains multiple content-addressed chunk objects under `.jj/repo/store/cas`.
    let cas_dir = dir.join(".jj/repo/store/cas");
    assert!(cas_dir.is_dir(), "expected native BLAKE3 CAS directory");
    let shard_count = std::fs::read_dir(&cas_dir).unwrap().count();
    assert!(
        shard_count >= 3,
        "expected multiple FastCDC CAS shards, got {shard_count}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn git_smart_http_bridge_advertises_jj_refs() {
    let dir = temp_dir("git-bridge");
    let svc = JjRepoService::new("Hephaestus Bot", "bot@example.invalid").unwrap();
    svc.init_internal_git_repo(&dir).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert("hello.txt".into(), b"hello git bridge\n".to_vec());
    let committed = svc
        .commit_files_and_bookmark(
            &dir,
            &JjCommitInput {
                bookmark: "main".into(),
                description: "commit for git export".into(),
                files,
            },
        )
        .await
        .unwrap();

    let bridge = GitSmartHttpBridge::new(svc);
    let (ctype, body) = bridge.info_refs(&dir, "git-upload-pack").await.unwrap();
    assert_eq!(ctype, "application/x-git-upload-pack-advertisement");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("# service=git-upload-pack"));
    assert!(text.contains("symref=HEAD:refs/heads/main"));
    assert!(text.contains("refs/heads/main"));
    assert!(text.contains(&committed.commit_id));

    let _ = std::fs::remove_dir_all(&dir);
}
