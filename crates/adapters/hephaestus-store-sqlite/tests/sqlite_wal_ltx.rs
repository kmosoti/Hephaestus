#![forbid(unsafe_code)]
//! Crash-recovery, WAL atomic idempotency, Zstd `"LTX1"` snapshots, SQL predicate pushdown,
//! and persisted `O(log N)` MMR inclusion proof tests for `hephaestus-store-sqlite`.

use hephaestus_core::{
    BlobDigest, BundleAccumulator, ChangeId, CommitId, DecisionDraft, DecisionStatus,
    IdempotencyKey, ObservationDraft, ObservationFilter, ObservationKind, OpId, RepoId, StreamKind,
    decode_ltx, verify_inclusion_proof,
};
use hephaestus_store::{BlobLocation, CatalogStore, CommitRef, LogStore, StoreError};
use hephaestus_store_sqlite::{LTX_SNAPSHOT_MAGIC, SqliteStore, restore_ltx_snapshot_zstd};
use rusqlite::Connection;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hep-sqlite-{tag}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn sqlite_wal_idempotency_logs_mmr_and_ltx1_crash_recovery() {
    let dir = temp_dir("wal-ltx");
    let live_db = dir.join("live.sqlite");
    let recovered_db = dir.join("recovered/catalog.sqlite");

    let store = SqliteStore::open(&live_db).unwrap();
    assert_eq!(store.page_size().unwrap(), 16_384);

    let repo = RepoId::parse("demo/hephaestus").unwrap();
    let ch1 = ChangeId::parse("kmpzsqxw").unwrap();
    let cm1 = CommitId::parse("1111aaaa2222bbbb3333cccc4444dddd").unwrap();
    let op1 = OpId::parse("aaaa1111bbbb2222").unwrap();

    // 1. Inline blob + packed GRNB0002 bundle.
    let small = b"inline-small-blob".to_vec();
    let small_digest = BlobDigest::of(&small);
    store.put_inline(&small_digest, &small).await.unwrap();

    let mut acc = BundleAccumulator::new(4096);
    let big = vec![0x7Cu8; 16 * 1024];
    let big_digest = BlobDigest(acc.push(big.clone()));
    let sealed = acc.seal().unwrap().unwrap();
    store.record_bundle(&sealed, "fs://bundle-1").await.unwrap();

    // 2. Atomic single-tx upsert_ref_idempotent.
    let ref_key = IdempotencyKey {
        repo_id: repo.clone(),
        stream_kind: StreamKind::JjOp,
        digest: BlobDigest::of(b"op-frame-1"),
    };
    let cref = CommitRef {
        repo_id: repo.clone(),
        bookmark: "main".into(),
        change_id: ch1.clone(),
        commit_id: cm1.clone(),
        op_id: op1.clone(),
        tree_blob_hash: small_digest.to_hex(),
        updated_ms: 150,
    };
    let first = store
        .upsert_ref_idempotent(&cref, &ref_key, b"ack-seq-1", 100)
        .await
        .unwrap();
    assert!(!first.already_applied);
    assert_eq!(first.ack_payload, b"ack-seq-1");

    let retry = store
        .upsert_ref_idempotent(&cref, &ref_key, b"different-ack-ignored", 200)
        .await
        .unwrap();
    assert!(retry.already_applied);
    assert_eq!(retry.ack_payload, b"ack-seq-1");

    // 3. Atomic append_decision_idempotent + MMR proofs.
    let d_draft = DecisionDraft {
        decision_id: "DEC-1".into(),
        change_id: ch1.clone(),
        op_id: op1.clone(),
        author: "architect".into(),
        status: DecisionStatus::Accepted,
        rationale: "Keep 16 KiB WAL pages".into(),
        alternatives: vec!["4 KiB default".into()],
        supersedes: None,
        recorded_at_ms: 300,
    };
    let d_key = IdempotencyKey {
        repo_id: repo.clone(),
        stream_kind: StreamKind::Decision,
        digest: BlobDigest::of(b"dec-1"),
    };
    let (d0, d_dup1) = store
        .append_decision_idempotent(&repo, d_draft.clone(), &d_key, 300)
        .await
        .unwrap();
    assert!(!d_dup1 && d0.seq == 0);
    let (d0_replay, d_dup2) = store
        .append_decision_idempotent(&repo, d_draft, &d_key, 305)
        .await
        .unwrap();
    assert!(d_dup2 && d0_replay == d0);
    assert_eq!(store.verify_decisions(&repo).await.unwrap(), 1);
    let d_proof = store.decision_inclusion_proof(&repo, 0).await.unwrap();
    assert!(verify_inclusion_proof(
        &d_proof,
        d0.record_hash,
        d0.mmr_root
    ));

    // 4. Atomic append_observation_idempotent + SQL predicate pushdown + MMR proofs.
    let mut last_obs = None;
    for i in 0u64..5 {
        let obs_key = IdempotencyKey {
            repo_id: repo.clone(),
            stream_kind: StreamKind::Observation,
            digest: BlobDigest::of(&i.to_le_bytes()),
        };
        let kind = if i % 2 == 0 {
            ObservationKind::TestReceipt
        } else {
            ObservationKind::O11yCustodyRef
        };
        let (rec, dup) = store
            .append_observation_idempotent(
                &repo,
                ObservationDraft {
                    observation_id: format!("OBS-{i}"),
                    kind,
                    change_id: ch1.clone(),
                    commit_id: cm1.clone(),
                    op_id: op1.clone(),
                    producer: "verifier".into(),
                    passed: Some(true),
                    summary: format!("Record {i}"),
                    payload_digest: big_digest,
                    custody_uri: None,
                    metadata_json: format!(r#"{{"b":{i},"a":"ok"}}"#),
                    recorded_at_ms: 400 + i,
                },
                &obs_key,
                400 + i,
            )
            .await
            .unwrap();
        assert!(!dup && rec.seq == i);
        last_obs = Some(rec);
    }
    let last_obs = last_obs.unwrap();
    assert_eq!(store.verify_observations(&repo).await.unwrap(), 5);
    let obs_proof = store.observation_inclusion_proof(&repo, 2).await.unwrap();
    let all_obs = store
        .query_observations(&repo, &ObservationFilter::default())
        .await
        .unwrap();
    assert!(verify_inclusion_proof(
        &obs_proof,
        all_obs[2].record_hash,
        last_obs.mmr_root
    ));

    // SQL predicate pushdown: kind + since_seq + limit.
    let paged = store
        .query_observations(
            &repo,
            &ObservationFilter {
                change_id: Some(ch1.clone()),
                kind: Some(ObservationKind::TestReceipt),
                since_seq: Some(2),
                limit: Some(1),
                ..ObservationFilter::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(paged.len(), 1);
    assert_eq!(paged[0].seq, 2);

    // 5. Export real Zstd-compressed "LTX1" snapshot, verify ltx_snapshots row, restore cleanly.
    let ltx_zst = store.export_ltx_snapshot_zstd().await.unwrap();
    assert_eq!(store.ltx_snapshot_count().await.unwrap(), 1);
    let raw_ltx = zstd::stream::decode_all(ltx_zst.as_slice()).unwrap();
    assert!(raw_ltx.starts_with(LTX_SNAPSHOT_MAGIC));
    let decoded = decode_ltx(&raw_ltx).unwrap();
    assert_eq!(decoded.header.page_size, 16_384);
    assert!(decoded.header.commit >= 1);
    drop(store);

    // Corrupt primary DB and verify atomic fsync restore.
    std::fs::write(&live_db, b"corrupted-primary-bytes").unwrap();
    let restored = restore_ltx_snapshot_zstd(&ltx_zst, &recovered_db).unwrap();
    assert_eq!(restored.page_size().unwrap(), 16_384);
    assert_eq!(
        restored.lookup_blob(&small_digest).await.unwrap(),
        Some(BlobLocation::Inline(small))
    );
    assert!(matches!(
        restored.lookup_blob(&big_digest).await.unwrap(),
        Some(BlobLocation::Packed { .. })
    ));
    assert_eq!(
        restored.check_idempotent(&ref_key).await.unwrap(),
        Some(b"ack-seq-1".to_vec())
    );
    assert_eq!(restored.verify_decisions(&repo).await.unwrap(), 1);
    assert_eq!(restored.verify_observations(&repo).await.unwrap(), 5);

    // Negative control: corrupted LTX1 bytes rejected on restore.
    let mut bad_ltx = raw_ltx.clone();
    bad_ltx[105] ^= 0xFF;
    assert!(restore_ltx_snapshot_zstd(&bad_ltx, dir.join("bad.sqlite")).is_err());

    // Negative control: tampering a decision row triggers ChainViolation.
    drop(restored);
    let raw_conn = Connection::open(&recovered_db).unwrap();
    raw_conn
        .execute(
            "UPDATE decisions SET rationale = 'tampered' WHERE seq = 0",
            [],
        )
        .unwrap();
    drop(raw_conn);

    let reopened = SqliteStore::open(&recovered_db).unwrap();
    let verify_err = reopened.verify_decisions(&repo).await.unwrap_err();
    assert!(matches!(verify_err, StoreError::ChainViolation(_)));

    let _ = std::fs::remove_dir_all(&dir);
}
