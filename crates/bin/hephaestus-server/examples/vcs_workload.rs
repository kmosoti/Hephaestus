#![forbid(unsafe_code)]
//! Standalone IPv6 workload benchmark for `hephaestus-server` over QUIC mTLS + HTTP/1.1 + `jj-lib`.

use hephaestus_core::{
    BlobDigest, ChangeId, CommitId, DecisionDraft, DecisionStatus, ObservationDraft,
    ObservationKind, OpId, RepoId,
};
use hephaestus_jj::{JjCommitInput, JjRepoService};
use hephaestus_server::{
    HephaestusEngine, HephaestusQuicClient, HephaestusQuicServer, HttpAuthMode, HttpBridgeConfig,
    QuicTlsIdentity, build_http_router_with_config,
};
use hephaestus_store::CommitRef;
use hephaestus_store_object::{
    NoopWebhookSink, ObjectStoreBackend, ObjectStoreConfig, PackedCasEngine,
};
use hephaestus_store_sqlite::SqliteStore;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

fn pct(sorted: &[u64], num: usize, den: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) * num) / den]
}

fn stats_json(vals: &mut [u64]) -> Value {
    vals.sort_unstable();
    let sum: u128 = vals.iter().map(|&v| u128::from(v)).sum();
    let avg = if vals.is_empty() {
        0
    } else {
        (sum / vals.len() as u128) as u64
    };
    json!({
        "count": vals.len(),
        "avg_us": avg / 1000,
        "p50_us": pct(vals, 50, 100) / 1000,
        "p95_us": pct(vals, 95, 100) / 1000,
        "p99_us": pct(vals, 99, 100) / 1000,
        "max_us": vals.last().copied().unwrap_or(0) / 1000
    })
}

#[tokio::main]
async fn main() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let work_dir = std::env::temp_dir().join(format!("hep-bench-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work_dir);
    let jj_dir = work_dir.join("jj-repo");
    let obj_dir = work_dir.join("objects");
    std::fs::create_dir_all(&obj_dir).unwrap();

    let sqlite = SqliteStore::open(work_dir.join("catalog.sqlite")).unwrap();
    let objects = Arc::new(
        ObjectStoreBackend::from_config(&ObjectStoreConfig::LocalFs {
            root: obj_dir,
            prefix: String::new(),
        })
        .unwrap(),
    );
    let cas = PackedCasEngine::new(Arc::new(sqlite.clone()), objects, 4 * 1024 * 1024);
    let jj = JjRepoService::new("Bench Bot", "bench@example.invalid").unwrap();
    jj.init_hephaestus_repo(&jj_dir).await.unwrap();

    let engine = Arc::new(HephaestusEngine::new(
        sqlite,
        cas,
        Arc::new(NoopWebhookSink),
        jj.clone(),
        Some(jj_dir.clone()),
    ));

    let server_id = QuicTlsIdentity::generate("hephaestus-bench").unwrap();
    let client_id = QuicTlsIdentity::generate("hephaestus-bench-client").unwrap();
    let quic_srv = HephaestusQuicServer::bind(
        "[::1]:0".parse().unwrap(),
        server_id.clone(),
        vec![client_id.fingerprint],
    )
    .unwrap();
    let quic_addr = quic_srv.local_addr();
    tokio::spawn(quic_srv.serve(Arc::clone(&engine)));

    let http_l = TcpListener::bind("[::1]:0").await.unwrap();
    let http_addr = http_l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            http_l,
            build_http_router_with_config(
                engine,
                HttpBridgeConfig {
                    auth: HttpAuthMode::AllowUnauthenticatedLoopback,
                    ..HttpBridgeConfig::default()
                },
            ),
        )
        .await;
    });

    let qcli = HephaestusQuicClient::connect(quic_addr, &client_id, server_id.fingerprint)
        .await
        .unwrap();
    let repo_id = RepoId::parse("bench/workload").unwrap();

    let mut inline_ns = Vec::new();
    let mut packed_ns = Vec::new();
    let mut stored_keys = Vec::new();

    for i in 0u32..16 {
        let small = format!("inline-src-{i:02}.rs").into_bytes();
        let t0 = Instant::now();
        let (h, dedup) = qcli
            .put_blob(repo_id.clone(), small.clone(), false)
            .await
            .unwrap();
        assert!(!dedup);
        inline_ns.push(t0.elapsed().as_nanos() as u64);
        stored_keys.push((h, small));

        let large = vec![(i as u8).wrapping_mul(13); 24 * 1024];
        let t1 = Instant::now();
        let (lh, ldedup) = qcli
            .put_blob(repo_id.clone(), large.clone(), false)
            .await
            .unwrap();
        assert!(!ldedup);
        packed_ns.push(t1.elapsed().as_nanos() as u64);
        stored_keys.push((lh, large));
    }

    let bundle_id = qcli.flush_bundle().await.unwrap();
    let mut files = BTreeMap::new();
    files.insert(
        "Cargo.toml".into(),
        b"[package]\nname = \"bench\"\n".to_vec(),
    );
    let committed = jj
        .commit_files_and_bookmark(
            &jj_dir,
            &JjCommitInput {
                bookmark: "main".into(),
                description: "bench snapshot".into(),
                files,
            },
        )
        .await
        .unwrap();

    let ch = ChangeId::parse(&committed.change_id).unwrap();
    let cm = CommitId::parse(&committed.commit_id).unwrap();
    let op = OpId::parse(&committed.op_id).unwrap();

    qcli.push_ref(CommitRef {
        repo_id: repo_id.clone(),
        bookmark: "main".into(),
        change_id: ch.clone(),
        commit_id: cm.clone(),
        op_id: op.clone(),
        tree_blob_hash: stored_keys[0].0.clone(),
        updated_ms: 1,
    })
    .await
    .unwrap();

    qcli.append_decision(
        repo_id.clone(),
        DecisionDraft {
            decision_id: "DEC-BENCH-1".into(),
            change_id: ch.clone(),
            op_id: op.clone(),
            author: "bench".into(),
            status: DecisionStatus::Accepted,
            rationale: "Benchmark GRNB0002 over IPv6 QUIC".into(),
            alternatives: vec![],
            supersedes: None,
            recorded_at_ms: 10,
        },
    )
    .await
    .unwrap();

    qcli.append_observation(
        repo_id.clone(),
        ObservationDraft {
            observation_id: "OBS-BENCH-1".into(),
            kind: ObservationKind::Benchmark,
            change_id: ch,
            commit_id: cm,
            op_id: op,
            producer: "vcs_workload".into(),
            passed: Some(true),
            summary: "Completed 60-read burst".into(),
            payload_digest: BlobDigest::of(b"bench-ok"),
            custody_uri: None,
            metadata_json: "{}".into(),
            recorded_at_ms: 20,
        },
    )
    .await
    .unwrap();

    let mut read_ns = Vec::with_capacity(60);
    let mut burst_bytes = 0usize;
    let tb0 = Instant::now();
    for i in 0..60 {
        let (h, expected) = &stored_keys[i % stored_keys.len()];
        let tr = Instant::now();
        let got = qcli.get_blob(h).await.unwrap().unwrap();
        assert_eq!(&got, expected);
        read_ns.push(tr.elapsed().as_nanos() as u64);
        burst_bytes += got.len();
    }
    let burst_ms = tb0.elapsed().as_secs_f64() * 1e3;

    let report = json!({
        "http_addr": http_addr.to_string(),
        "quic_addr": quic_addr.to_string(),
        "flushed_bundle": bundle_id,
        "put_inline_us": stats_json(&mut inline_ns),
        "put_packed_us": stats_json(&mut packed_ns),
        "burst_reads": 60,
        "burst_bytes": burst_bytes,
        "burst_total_ms": burst_ms,
        "read_us": stats_json(&mut read_ns)
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    let _ = std::fs::remove_dir_all(&work_dir);
}
