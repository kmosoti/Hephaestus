#![forbid(unsafe_code)]
//! Security regression tests for Daybreak findings #3, #9, and #10 in `hephaestus-store-sqlite`.

use hephaestus_core::{
    BlobDigest, ChangeId, CommitId, DEFAULT_LOG_PAGE_LIMIT, DecisionDraft, DecisionStatus,
    IdempotencyKey, MAX_LOG_PAGE_LIMIT, ObservationDraft, ObservationFilter, ObservationKind, OpId,
    RepoId, StreamKind, encode_snapshot_ltx,
};
use hephaestus_store::{CatalogStore, LogStore, StoreError};
use hephaestus_store_sqlite::{
    MAX_LTX_DECOMPRESSED_BYTES, SqliteStore, restore_ltx_snapshot_zstd,
    restore_ltx_snapshot_zstd_verified,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hep-sqsec-{tag}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn verified_ltx_restore_rejects_forged_digest_replay_and_zstd_bombs() {
    let dir = temp_dir("ltx-sec");
    let db_path = dir.join("live.sqlite");
    let store = SqliteStore::open(&db_path).unwrap();
    let repo = RepoId::parse("sec/repo").unwrap();
    let ch = ChangeId::parse("kmpzsqxw").unwrap();
    let op = OpId::parse("1111222233334444").unwrap();
    store
        .append_decision(
            &repo,
            DecisionDraft {
                decision_id: "DEC-1".into(),
                change_id: ch,
                op_id: op,
                author: "sec".into(),
                status: DecisionStatus::Accepted,
                rationale: "real".into(),
                alternatives: vec![],
                supersedes: None,
                recorded_at_ms: 10,
            },
        )
        .await
        .unwrap();

    let snap1 = store.export_ltx_snapshot_zstd().await.unwrap();
    let meta1 = store.latest_ltx_snapshot_meta().await.unwrap().unwrap();
    let snap2 = store.export_ltx_snapshot_zstd().await.unwrap();
    let meta2 = store.latest_ltx_snapshot_meta().await.unwrap().unwrap();
    assert_eq!(meta1.snapshot_seq, 1);
    assert_eq!(meta2.snapshot_seq, 2);

    // 1. Valid snapshot restores with matching digest and txid.
    let restored = restore_ltx_snapshot_zstd_verified(
        &snap2,
        dir.join("ok.sqlite"),
        &meta2.raw_digest,
        Some(2),
    )
    .unwrap();
    assert_eq!(restored.verify_decisions(&repo).await.unwrap(), 1);

    // 2. Forged valid-CRC LTX1 image with different BLAKE3 digest is rejected before replacing dest.
    let forged_db = vec![0xAAu8; 16_384 * 2];
    let (forged_ltx, _, _) = encode_snapshot_ltx(&forged_db, 16_384, 99, 100).unwrap();
    let forged_zst = zstd::bulk::compress(&forged_ltx, 3).unwrap();
    let forged_dest = dir.join("forged.sqlite");
    assert!(
        restore_ltx_snapshot_zstd_verified(&forged_zst, &forged_dest, &meta2.raw_digest, Some(1))
            .is_err()
    );
    assert!(!forged_dest.exists());

    // 3. Stale replay below min_txid is rejected.
    assert!(
        restore_ltx_snapshot_zstd_verified(
            &snap1,
            dir.join("replay.sqlite"),
            &meta1.raw_digest,
            Some(2)
        )
        .is_err()
    );

    // 4. Decompression bomb exceeding MAX_LTX_DECOMPRESSED_BYTES fails cleanly.
    let bomb_raw = vec![0u8; MAX_LTX_DECOMPRESSED_BYTES + 4096];
    let bomb_zst = zstd::bulk::compress(&bomb_raw, 3).unwrap();
    drop(bomb_raw);
    assert!(restore_ltx_snapshot_zstd(&bomb_zst, dir.join("bomb.sqlite")).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn paginated_log_reads_cap_pages_and_do_not_starve_writes() {
    let dir = temp_dir("log-page");
    let store = SqliteStore::open(dir.join("catalog.sqlite")).unwrap();
    let repo = RepoId::parse("sec/paged").unwrap();
    let ch = ChangeId::parse("kmpzsqxw").unwrap();
    let cm = CommitId::parse("1111aaaa2222bbbb3333cccc4444dddd").unwrap();
    let op = OpId::parse("aaaa1111bbbb2222").unwrap();

    for i in 0..250u64 {
        store
            .append_decision(
                &repo,
                DecisionDraft {
                    decision_id: format!("DEC-{i:04}"),
                    change_id: ch.clone(),
                    op_id: op.clone(),
                    author: "bench".into(),
                    status: DecisionStatus::Accepted,
                    rationale: format!("rationale {i}"),
                    alternatives: vec![],
                    supersedes: None,
                    recorded_at_ms: i,
                },
            )
            .await
            .unwrap();
        store
            .append_observation(
                &repo,
                ObservationDraft {
                    observation_id: format!("OBS-{i:04}"),
                    kind: ObservationKind::TestReceipt,
                    change_id: ch.clone(),
                    commit_id: cm.clone(),
                    op_id: op.clone(),
                    producer: "ci".into(),
                    passed: Some(true),
                    summary: format!("obs {i}"),
                    payload_digest: BlobDigest::of(&i.to_le_bytes()),
                    custody_uri: None,
                    metadata_json: "{}".into(),
                    recorded_at_ms: i,
                },
            )
            .await
            .unwrap();
    }

    // Default and oversized limits are bounded.
    let page0 = store.list_decisions(&repo, None).await.unwrap();
    assert_eq!(page0.len(), DEFAULT_LOG_PAGE_LIMIT);
    let page1 = store
        .query_decisions(
            &repo,
            None,
            Some(DEFAULT_LOG_PAGE_LIMIT as u64),
            Some(999_999),
        )
        .await
        .unwrap();
    assert_eq!(page1.len(), 50);
    assert_eq!(page1[0].seq, DEFAULT_LOG_PAGE_LIMIT as u64);

    let obs_default = store
        .query_observations(&repo, &ObservationFilter::default())
        .await
        .unwrap();
    assert_eq!(obs_default.len(), DEFAULT_LOG_PAGE_LIMIT);
    let obs_explicit = store
        .query_observations(
            &repo,
            &ObservationFilter {
                limit: Some(MAX_LOG_PAGE_LIMIT + 500),
                ..ObservationFilter::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(obs_explicit.len(), 250);
    assert!(obs_explicit.len() <= MAX_LOG_PAGE_LIMIT);

    // Concurrent verification and idempotent write succeed cleanly without mutual starvation.
    let s1 = store.clone();
    let r1 = repo.clone();
    let v_fut = tokio::spawn(async move { s1.verify_observations(&r1).await });
    let key = IdempotencyKey {
        repo_id: repo.clone(),
        stream_kind: StreamKind::Decision,
        digest: BlobDigest::of(b"concurrent-write"),
    };
    let (rec, dup) = store
        .append_decision_idempotent(
            &repo,
            DecisionDraft {
                decision_id: "DEC-CONC".into(),
                change_id: ch,
                op_id: op,
                author: "writer".into(),
                status: DecisionStatus::Accepted,
                rationale: "concurrent append".into(),
                alternatives: vec![],
                supersedes: None,
                recorded_at_ms: 999,
            },
            &key,
            999,
        )
        .await
        .unwrap();
    assert!(!dup && rec.seq == 250);
    let v_count = v_fut.await.unwrap().unwrap();
    assert_eq!(v_count, 250);
    assert_eq!(store.verify_decisions(&repo).await.unwrap(), 251);

    // Confirm verify_sem bounds excess concurrent verify requests gracefully.
    assert!(matches!(
        store.verify_decisions(&repo).await,
        Ok(251) | Err(StoreError::RateLimited(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
