#![forbid(unsafe_code)]
//! Full IPv6 loopback E2E tests for `hephaestus-server` (QUIC Ed25519 mTLS, idempotency,
//! Decision Log, Observation Logs, `jj-lib`, Git smart-HTTP bridge, and push webhooks).

use axum::routing::post;
use axum::{Json, Router};
use hephaestus_core::{
    BlobDigest, ChangeId, CommitId, DecisionDraft, DecisionStatus, ObservationDraft,
    ObservationFilter, ObservationKind, OpId, RepoId,
};
use hephaestus_jj::{JjCommitInput, JjRepoService};
use hephaestus_server::{
    HephaestusEngine, HephaestusQuicClient, HephaestusQuicServer, QuicTlsIdentity,
    build_authenticated_http_router,
};
use hephaestus_store::{CommitRef, PushWebhookEvent};
use hephaestus_store_object::{
    HttpWebhookSink, ObjectStoreBackend, ObjectStoreConfig, PackedCasEngine,
};
use hephaestus_store_sqlite::SqliteStore;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::process::Command;

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hep-e2e-{tag}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn ipv6_quic_mtls_idempotency_logs_jj_git_bridge_and_webhooks_e2e() {
    let dir = temp_dir("full");
    let jj_dir = dir.join("jj-repo");
    let obj_dir = dir.join("objects");
    std::fs::create_dir_all(&obj_dir).unwrap();

    // 1. Spawn IPv6 [::1]:0 webhook receiver.
    let hooks: Arc<Mutex<Vec<PushWebhookEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let hooks_srv = Arc::clone(&hooks);
    let hook_app = Router::new().route(
        "/v1/ci/push",
        post(move |Json(ev): Json<PushWebhookEvent>| {
            let store = Arc::clone(&hooks_srv);
            async move {
                store.lock().unwrap().push(ev);
                "ok"
            }
        }),
    );
    let hook_l = TcpListener::bind("[::1]:0").await.unwrap();
    let hook_addr = hook_l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(hook_l, hook_app).await;
    });
    let webhook = Arc::new(HttpWebhookSink::new(format!("http://{hook_addr}/v1/ci/push")).unwrap());

    // 2. Initialize jj internal-git repo + SQLite WAL + LocalFS object backend.
    let jj = JjRepoService::new("Hephaestus E2E", "e2e@example.invalid").unwrap();
    jj.init_internal_git_repo(&jj_dir).await.unwrap();
    let mut files = BTreeMap::new();
    files.insert("README.md".into(), b"# Hephaestus E2E\n".to_vec());
    let committed = jj
        .commit_files_and_bookmark(
            &jj_dir,
            &JjCommitInput {
                bookmark: "main".into(),
                description: "seed repo".into(),
                files,
            },
        )
        .await
        .unwrap();

    let sqlite = SqliteStore::open(dir.join("catalog.sqlite")).unwrap();
    let objects = Arc::new(
        ObjectStoreBackend::from_config(&ObjectStoreConfig::LocalFs {
            root: obj_dir,
            prefix: String::new(),
        })
        .unwrap(),
    );
    let cas = PackedCasEngine::new(Arc::new(sqlite.clone()), objects, 4 * 1024 * 1024);
    let engine = Arc::new(HephaestusEngine::new(
        sqlite,
        cas,
        webhook,
        jj.clone(),
        Some(jj_dir.clone()),
    ));

    // 3. Start IPv6 QUIC mTLS server + IPv6 HTTP/1.1 bridge.
    let server_id = QuicTlsIdentity::generate("hephaestus-server").unwrap();
    let client_id = QuicTlsIdentity::generate("hephaestus-client").unwrap();
    let rogue_id = QuicTlsIdentity::generate("untrusted-client").unwrap();

    let quic_srv = HephaestusQuicServer::bind(
        "[::1]:0".parse().unwrap(),
        server_id.clone(),
        vec![client_id.fingerprint],
    )
    .unwrap();
    let quic_addr = quic_srv.local_addr();
    tokio::spawn(quic_srv.serve(Arc::clone(&engine)));

    let http_token = "e2e-daybreak-bearer-token-value";
    let http_token_hash: [u8; 32] = Sha256::digest(http_token.as_bytes()).into();
    let http_l = TcpListener::bind("[::1]:0").await.unwrap();
    let http_addr = http_l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            http_l,
            build_authenticated_http_router(engine, http_token_hash),
        )
        .await;
    });

    // 4. Negative controls: untrusted client cert AND wrong server pin MUST be rejected.
    assert!(
        HephaestusQuicClient::connect(quic_addr, &rogue_id, server_id.fingerprint)
            .await
            .is_err(),
        "untrusted client certificate must be rejected by mTLS pin"
    );
    assert!(
        HephaestusQuicClient::connect(quic_addr, &client_id, rogue_id.fingerprint)
            .await
            .is_err(),
        "wrong server certificate fingerprint must be rejected by client pin"
    );

    // 5. Authorized mTLS QUIC client: multiplexed blobs, idempotent retry, Decision & Observation logs.
    let qcli = HephaestusQuicClient::connect(quic_addr, &client_id, server_id.fingerprint)
        .await
        .unwrap();
    let repo_id = RepoId::parse("e2e/repo").unwrap();

    let small = b"small inline jj metadata".to_vec();
    let (small_hex, small_dup1) = qcli
        .put_blob(repo_id.clone(), small.clone(), false)
        .await
        .unwrap();
    assert!(!small_dup1);
    let (small_hex_retry, small_dup2) = qcli
        .put_blob(repo_id.clone(), small.clone(), false)
        .await
        .unwrap();
    assert_eq!(small_hex, small_hex_retry);
    assert!(small_dup2);

    let big = vec![0x9Au8; 24 * 1024];
    let (big_hex, _) = qcli
        .put_blob(repo_id.clone(), big.clone(), false)
        .await
        .unwrap();
    let flushed = qcli.flush_bundle().await.unwrap();
    assert!(flushed.is_some());
    assert_eq!(qcli.get_blob(&small_hex).await.unwrap(), Some(small));
    assert_eq!(qcli.get_blob(&big_hex).await.unwrap(), Some(big));

    let ch = ChangeId::parse(&committed.change_id).unwrap();
    let cm = CommitId::parse(&committed.commit_id).unwrap();
    let op = OpId::parse(&committed.op_id).unwrap();

    let commit_ref = CommitRef {
        repo_id: repo_id.clone(),
        bookmark: "main".into(),
        change_id: ch.clone(),
        commit_id: cm.clone(),
        op_id: op.clone(),
        tree_blob_hash: small_hex.clone(),
        updated_ms: 100,
    };
    let (notified, ref_dup1) = qcli.push_ref(commit_ref.clone()).await.unwrap();
    assert!(notified && !ref_dup1);
    let (notified2, ref_dup2) = qcli.push_ref(commit_ref).await.unwrap();
    assert!(!notified2 && ref_dup2);
    assert_eq!(
        hooks.lock().unwrap().len(),
        1,
        "idempotent retry must not double-fire webhook"
    );

    // Decision Log idempotency & query via QUIC + HTTP.
    let dec_draft = DecisionDraft {
        decision_id: "DEC-E2E-1".into(),
        change_id: ch.clone(),
        op_id: op.clone(),
        author: "e2e-agent".into(),
        status: DecisionStatus::Accepted,
        rationale: "Use Ed25519 mTLS QUIC pinning".into(),
        alternatives: vec!["Insecure plaintext".into()],
        supersedes: None,
        recorded_at_ms: 200,
    };
    let (d_rec, d_dup1) = qcli
        .append_decision(repo_id.clone(), dec_draft.clone())
        .await
        .unwrap();
    assert!(!d_dup1);
    let (d_rec2, d_dup2) = qcli
        .append_decision(repo_id.clone(), dec_draft)
        .await
        .unwrap();
    assert!(d_dup2);
    assert_eq!(d_rec, d_rec2);
    assert_eq!(
        qcli.query_decisions(repo_id.clone(), Some(ch.clone()))
            .await
            .unwrap()
            .len(),
        1
    );

    // Orthogonal Observation Logs via QUIC + HTTP bridge query.
    let obs_draft = ObservationDraft {
        observation_id: "OBS-E2E-1".into(),
        kind: ObservationKind::VerifierVerdict,
        change_id: ch.clone(),
        commit_id: cm.clone(),
        op_id: op.clone(),
        producer: "verifier-core".into(),
        passed: Some(true),
        summary: "mTLS QUIC E2E verified".into(),
        payload_digest: BlobDigest::of(b"verdict-ok"),
        custody_uri: Some("urn:o11y:verdict:1".into()),
        metadata_json: "{}".into(),
        recorded_at_ms: 300,
    };
    let (o_rec, o_dup1) = qcli
        .append_observation(repo_id.clone(), obs_draft.clone())
        .await
        .unwrap();
    assert!(!o_dup1);
    let (o_rec2, o_dup2) = qcli
        .append_observation(repo_id.clone(), obs_draft)
        .await
        .unwrap();
    assert!(o_dup2 && o_rec == o_rec2);
    assert_eq!(
        qcli.query_observations(
            repo_id.clone(),
            ObservationFilter {
                change_id: Some(ch),
                kind: Some(ObservationKind::VerifierVerdict),
                ..ObservationFilter::default()
            }
        )
        .await
        .unwrap()
        .len(),
        1
    );

    // 6. HTTP/1.1 bridge verification + Git smart-HTTP clone/push -> jj OpLog sync.
    let http = reqwest::Client::new();
    let health: serde_json::Value = http
        .get(format!("http://{http_addr}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");

    let anon_verify = http
        .get(format!("http://{http_addr}/v1/decisions/e2e%2Frepo/verify"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon_verify.status().as_u16(), 401);

    let verify_dec: serde_json::Value = http
        .get(format!("http://{http_addr}/v1/decisions/e2e%2Frepo/verify"))
        .bearer_auth(http_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verify_dec["verified_count"], 1);

    let auth_hdr = format!("http.extraHeader=Authorization: Bearer {http_token}");
    let clone_dir = dir.join("git-clone");
    let git_url = format!("http://{http_addr}/git/demo");
    let clone_out = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", &auth_hdr, "clone", &git_url])
        .arg(&clone_dir)
        .output()
        .await
        .unwrap();
    assert!(
        clone_out.status.success(),
        "git clone: {}",
        String::from_utf8_lossy(&clone_out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(clone_dir.join("README.md")).unwrap(),
        "# Hephaestus E2E\n"
    );

    // Push a commit over Git smart-HTTP and verify jj OpLog records the imported push.
    std::fs::write(clone_dir.join("pushed.txt"), "pushed via smart-http\n").unwrap();
    for args in [
        vec!["config", "user.name", "Git Bridge Tester"],
        vec!["config", "user.email", "git@example.invalid"],
        vec!["add", "pushed.txt"],
        vec!["commit", "-m", "smart-http push"],
        vec!["-c", &auth_hdr, "push", "origin", "HEAD:main"],
    ] {
        let out = Command::new("git")
            .env("GIT_TERMINAL_PROMPT", "0")
            .current_dir(&clone_dir)
            .args(&args)
            .output()
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let ops = jj.list_op_log(&jj_dir, 10).await.unwrap();
    assert!(
        ops.iter()
            .any(|o| o.description.contains("import git smart-http push")),
        "expected jj op log to contain imported smart-http push: {ops:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
