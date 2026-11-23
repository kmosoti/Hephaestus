#![forbid(unsafe_code)]
//! Wave 2 hardening tests for `hephaestus-server`: persisted SPKI TLS identity, >16 MiB chunked
//! QUIC streaming, multi-repo Git validation + CAS/webhook sync, and `"LTX1"` snapshot shipping.

use axum::routing::post;
use axum::{Json, Router};
use hephaestus_core::RepoId;
use hephaestus_jj::{JjCommitInput, JjRepoService};
use hephaestus_server::{
    HephaestusEngine, HephaestusQuicClient, HephaestusQuicServer, MAX_QUIC_FRAME_BYTES,
    QuicTlsIdentity, build_authenticated_http_router, build_quinn_server_config, ct_eq_32,
    validate_git_repo_segment,
};
use hephaestus_store::{ObjectBackend as _, PushWebhookEvent};
use hephaestus_store_object::{
    HttpWebhookSink, ObjectStoreBackend, ObjectStoreConfig, PackedCasEngine,
};
use hephaestus_store_sqlite::{SqliteStore, restore_ltx_snapshot_zstd};
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
    let dir = std::env::temp_dir().join(format!("hep-w2-{tag}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn persisted_tls_identity_keeps_spki_pin_and_rejects_empty_allowlist() {
    let dir = temp_dir("tls");
    let key_path = dir.join("tls-ed25519.pem");
    let id1 = QuicTlsIdentity::load_or_generate(&key_path, "hephaestus-node").unwrap();
    let id2 = QuicTlsIdentity::load_or_generate(&key_path, "hephaestus-node").unwrap();
    assert!(ct_eq_32(&id1.fingerprint, &id2.fingerprint));
    assert_eq!(id1.fingerprint_hex, id2.fingerprint_hex);

    let mut wrong = id1.fingerprint;
    wrong[31] ^= 1;
    assert!(!ct_eq_32(&id1.fingerprint, &wrong));

    assert!(build_quinn_server_config(&id1, vec![]).is_err());

    assert!(validate_git_repo_segment("repo_1.foo-bar").is_ok());
    for bad in ["", ".", "..", "a/b", "repo with spaces", "../escape"] {
        assert!(
            validate_git_repo_segment(bad).is_err(),
            "expected error for `{bad}`"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn quic_streams_over_16mib_and_git_push_syncs_cas_webhook_and_ltx1_shipper() {
    let dir = temp_dir("stream");
    let repos_root = dir.join("repos");
    let repo_alpha = repos_root.join("alpha");
    let obj_dir = dir.join("objects");
    std::fs::create_dir_all(&obj_dir).unwrap();

    let hooks: Arc<Mutex<Vec<PushWebhookEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let hooks_srv = Arc::clone(&hooks);
    let hook_app = Router::new().route(
        "/hook",
        post(move |Json(ev): Json<PushWebhookEvent>| {
            let h = Arc::clone(&hooks_srv);
            async move {
                h.lock().unwrap().push(ev);
                "ok"
            }
        }),
    );
    let hook_l = TcpListener::bind("[::1]:0").await.unwrap();
    let hook_addr = hook_l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(hook_l, hook_app).await;
    });
    let webhook = Arc::new(HttpWebhookSink::new(format!("http://{hook_addr}/hook")).unwrap());

    let jj = JjRepoService::new("Wave2 Bot", "w2@example.invalid").unwrap();
    jj.init_internal_git_repo(&repo_alpha).await.unwrap();
    let mut seed_files = BTreeMap::new();
    seed_files.insert("seed.txt".into(), b"hello\n".to_vec());
    jj.commit_files_and_bookmark(
        &repo_alpha,
        &JjCommitInput {
            bookmark: "main".into(),
            description: "seed".into(),
            files: seed_files,
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
    let cas = PackedCasEngine::new(Arc::new(sqlite.clone()), objects.clone(), 4 * 1024 * 1024);
    let engine = Arc::new(HephaestusEngine::new(
        sqlite.clone(),
        cas,
        webhook,
        jj,
        Some(repos_root),
    ));

    let server_id = QuicTlsIdentity::generate("hephaestus-w2").unwrap();
    let client_id = QuicTlsIdentity::generate("hephaestus-w2-cli").unwrap();
    let quic_srv = HephaestusQuicServer::bind(
        "[::1]:0".parse().unwrap(),
        server_id.clone(),
        vec![client_id.fingerprint],
    )
    .unwrap();
    let quic_addr = quic_srv.local_addr();
    tokio::spawn(quic_srv.serve(Arc::clone(&engine)));

    let http_token = "wave2-hardening-bearer-token";
    let http_token_hash: [u8; 32] = Sha256::digest(http_token.as_bytes()).into();
    let http_l = TcpListener::bind("[::1]:0").await.unwrap();
    let http_addr = http_l.local_addr().unwrap();
    let http_engine = Arc::clone(&engine);
    tokio::spawn(async move {
        let _ = axum::serve(
            http_l,
            build_authenticated_http_router(http_engine, http_token_hash),
        )
        .await;
    });

    // 1. Upload + download a 15 MiB multi-chunk blob over QUIC streaming (<= 16 MiB cap),
    //    and confirm > 16 MiB is rejected.
    let qcli = HephaestusQuicClient::connect(quic_addr, &client_id, server_id.fingerprint)
        .await
        .unwrap();
    let big_15m = vec![0x5Au8; 15 * 1024 * 1024];
    let (big_hex, dup) = qcli
        .put_blob(RepoId::parse("w2/big").unwrap(), big_15m.clone(), false)
        .await
        .unwrap();
    assert!(!dup);
    let got_15m = qcli.get_blob(&big_hex).await.unwrap().unwrap();
    assert_eq!(got_15m.len(), big_15m.len());
    assert_eq!(got_15m, big_15m);
    assert!(
        qcli.put_blob(
            RepoId::parse("w2/big").unwrap(),
            vec![0x11u8; MAX_QUIC_FRAME_BYTES + 1],
            false
        )
        .await
        .is_err()
    );

    // 2. Reject invalid repo path on authenticated Git smart-HTTP with 400 (and anon with 401).
    let http = reqwest::Client::new();
    let anon_resp = http
        .get(format!(
            "http://{http_addr}/git/alpha/info/refs?service=git-upload-pack"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(anon_resp.status().as_u16(), 401);
    let bad_resp = http
        .get(format!(
            "http://{http_addr}/git/bad$repo/info/refs?service=git-upload-pack"
        ))
        .bearer_auth(http_token)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_resp.status().as_u16(), 400);

    // 3. Clone & push to multi-repo `/git/alpha`, confirming streaming receive-pack fires webhook + CAS sync.
    let auth_header = format!("Authorization: Bearer {http_token}");
    let clone_dir = dir.join("clone-alpha");
    let git_url = format!("http://{http_addr}/git/alpha");
    assert!(
        Command::new("git")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                &format!("http.extraHeader={auth_header}"),
                "clone",
                &git_url,
            ])
            .arg(&clone_dir)
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    std::fs::write(clone_dir.join("new.txt"), "wave2 push\n").unwrap();
    for args in [
        vec!["config", "user.name", "W2"],
        vec!["config", "user.email", "w2@example.invalid"],
        vec!["add", "new.txt"],
        vec!["commit", "-m", "wave2 push"],
        vec![
            "-c",
            &format!("http.extraHeader={auth_header}"),
            "push",
            "origin",
            "HEAD:main",
        ],
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
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(
        !hooks.lock().unwrap().is_empty(),
        "expected git-receive-pack to fire push webhook"
    );

    // 4. Ship real Zstd-compressed "LTX1" snapshot via engine and verify end-to-end verified restore.
    let receipt = engine.ship_ltx_snapshot_manifest().await.unwrap();
    assert_eq!(sqlite.ltx_snapshot_count().await.unwrap(), 1);
    let uploaded = objects.get_bundle(&receipt.object_id).await.unwrap();
    let restored = restore_ltx_snapshot_zstd(&uploaded, dir.join("restored.sqlite")).unwrap();
    assert_eq!(restored.page_size().unwrap(), 16_384);
    let verified = engine
        .restore_ltx_snapshot_verified(
            &receipt.object_id,
            &dir.join("verified-restored.sqlite"),
            &receipt.raw_digest,
            Some(&receipt.snapshot_digest),
            Some(receipt.txid),
        )
        .await
        .unwrap();
    assert_eq!(verified.page_size().unwrap(), 16_384);

    let _ = std::fs::remove_dir_all(&dir);
}
