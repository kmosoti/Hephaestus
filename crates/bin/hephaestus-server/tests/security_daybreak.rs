#![forbid(unsafe_code)]
//! Security regression tests for Daybreak findings #2, #3, #4, #8, and #15 in `hephaestus-server`.

use hephaestus_core::RepoId;
use hephaestus_jj::JjRepoService;
use hephaestus_server::{
    HephaestusEngine, HephaestusQuicClient, HephaestusQuicServer, HttpAuthMode, HttpBridgeConfig,
    MAX_QUIC_FRAME_BYTES, QuicRequest, QuicResponse, QuicTlsIdentity,
    build_http_router_with_config, load_http_auth_token_hash, write_stream_message,
};
use hephaestus_store_object::{
    NoopWebhookSink, ObjectStoreBackend, ObjectStoreConfig, PackedCasEngine,
};
use hephaestus_store_sqlite::SqliteStore;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hep-srvsec-{tag}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_test_engine(dir: &std::path::Path) -> Arc<HephaestusEngine> {
    let sqlite = SqliteStore::open(dir.join("catalog.sqlite")).unwrap();
    let obj_dir = dir.join("objects");
    std::fs::create_dir_all(&obj_dir).unwrap();
    let objects = Arc::new(
        ObjectStoreBackend::from_config(&ObjectStoreConfig::LocalFs {
            root: obj_dir,
            prefix: String::new(),
        })
        .unwrap(),
    );
    let cas = PackedCasEngine::new(Arc::new(sqlite.clone()), objects, 4 * 1024 * 1024);
    let jj = JjRepoService::new("Sec", "sec@example.invalid").unwrap();
    Arc::new(HephaestusEngine::new(
        sqlite,
        cas,
        Arc::new(NoopWebhookSink),
        jj,
        None,
    ))
}

#[cfg(unix)]
#[test]
fn token_file_loader_enforces_o_nofollow_and_0600_mode_and_cli_bind_guard() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let dir = temp_dir("tok");

    let secret_file = dir.join("http.token");
    std::fs::write(&secret_file, "super-secret-bearer-token-value\n").unwrap();
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        load_http_auth_token_hash(&secret_file).is_err(),
        "0644 token file must be rejected"
    );

    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let h = load_http_auth_token_hash(&secret_file).unwrap();
    let expected: [u8; 32] = Sha256::digest(b"super-secret-bearer-token-value").into();
    assert_eq!(h, expected);

    let link_file = dir.join("http.link");
    symlink(&secret_file, &link_file).unwrap();
    assert!(
        load_http_auth_token_hash(&link_file).is_err(),
        "symlink token file must be rejected via O_NOFOLLOW"
    );

    // Binary refuses non-loopback HTTP bind without --http-auth-token-file (even with loopback opt-in).
    let bin = env!("CARGO_BIN_EXE_hephaestus-server");
    let non_loop = std::process::Command::new(bin)
        .args([
            "--http-bind",
            "[fd00:db8::1]:8081",
            "--quic-bind",
            "[::1]:8443",
            "--data-dir",
            dir.to_str().unwrap(),
            "--allow-unauthenticated-loopback-http",
            "--dev-ephemeral",
        ])
        .output()
        .unwrap();
    assert!(!non_loop.status.success());

    // Binary refuses loopback HTTP bind without token file OR explicit opt-in.
    let unauth_loop = std::process::Command::new(bin)
        .args([
            "--http-bind",
            "[::1]:8081",
            "--quic-bind",
            "[::1]:8443",
            "--data-dir",
            dir.to_str().unwrap(),
            "--dev-ephemeral",
        ])
        .output()
        .unwrap();
    assert!(!unauth_loop.status.success());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn http_auth_concurrency_limits_and_sanitized_errors() {
    let dir = temp_dir("http-auth");
    let engine = build_test_engine(&dir);

    let token = "daybreak-secret-http-token";
    let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let router = build_http_router_with_config(
        Arc::clone(&engine),
        HttpBridgeConfig {
            auth: HttpAuthMode::BearerSha256(token_hash),
            max_concurrency: 8,
            max_git_children: 2,
            max_body_bytes: 1024,
            request_timeout: Duration::from_secs(5),
        },
    );
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let client = reqwest::Client::new();
    // /health remains accessible anonymously.
    let h = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(h.status().as_u16(), 200);

    // Every non-health route rejects anonymous and bad-token callers with 401.
    for (method, path) in [
        ("GET", "/v1/stats"),
        ("POST", "/v1/flush"),
        ("POST", "/v1/blobs"),
        ("GET", "/v1/blobs/0000"),
        ("POST", "/v1/push"),
        ("GET", "/v1/refs/demo"),
        ("POST", "/v1/decisions"),
        ("GET", "/v1/decisions/demo"),
        ("GET", "/v1/decisions/demo/verify"),
        ("POST", "/v1/observations"),
        ("GET", "/v1/observations/demo"),
        ("GET", "/v1/observations/demo/verify"),
        ("GET", "/v1/jj/ops"),
        ("GET", "/git/demo/info/refs?service=git-upload-pack"),
        ("POST", "/git/demo/git-upload-pack"),
        ("POST", "/git/demo/git-receive-pack"),
    ] {
        let req = match method {
            "POST" => client.post(format!("http://{addr}{path}")),
            _ => client.get(format!("http://{addr}{path}")),
        };
        assert_eq!(
            req.send().await.unwrap().status().as_u16(),
            401,
            "{method} {path} must require Bearer auth"
        );
    }

    // Authenticated request fails on unconfigured jj_repo with sanitized message (no filesystem paths).
    let git_err = client
        .get(format!("http://{addr}/v1/jj/ops"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(git_err.status().as_u16(), 404);
    let err_body = git_err.text().await.unwrap();
    assert!(err_body.contains("ref=err-"));
    assert!(!err_body.contains("/tmp"));
    assert!(!err_body.contains("catalog.sqlite"));

    // Oversized Content-Length rejected with 413 before spawning git.
    let too_big = client
        .post(format!("http://{addr}/git/demo/git-receive-pack"))
        .bearer_auth(token)
        .header("content-length", "2048")
        .body(vec![b'a'; 2048])
        .send()
        .await
        .unwrap();
    assert_eq!(too_big.status().as_u16(), 413);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn quic_rejects_unexpected_binary_payload_and_ltx_restore_verifies_digest_and_txid() {
    let dir = temp_dir("quic-ltx");
    let engine = build_test_engine(&dir);

    let server_id = QuicTlsIdentity::generate("srv").unwrap();
    let client_id = QuicTlsIdentity::generate("cli").unwrap();
    let srv = HephaestusQuicServer::bind(
        "[::1]:0".parse().unwrap(),
        server_id.clone(),
        vec![client_id.fingerprint],
    )
    .unwrap()
    .with_memory_budget(32 * 1024 * 1024, Duration::from_secs(10));
    let addr = srv.local_addr();
    tokio::spawn(srv.serve(Arc::clone(&engine)));

    let qcli = HephaestusQuicClient::connect(addr, &client_id, server_id.fingerprint)
        .await
        .unwrap();

    // Verify QUIC sanitized error when querying unconfigured jj ops.
    let err = qcli
        .request(QuicRequest::JjListOps { limit: 10 })
        .await
        .unwrap_err();
    assert!(err.contains("ref=err-"));
    assert!(!err.contains("no jj repository"));

    // Verify non-blob request carrying trailing binary payload is rejected before payload allocation.
    let cfg =
        hephaestus_server::build_quinn_client_config(&client_id, server_id.fingerprint).unwrap();
    let client_ep = {
        let mut ep = quinn::Endpoint::client("[::1]:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(cfg);
        ep
    };
    let conn = client_ep
        .connect(addr, "hephaestus-node")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let hdr_bytes = serde_json::to_vec(&QuicRequest::Health).unwrap();
    send.write_all(&(hdr_bytes.len() as u32).to_be_bytes())
        .await
        .unwrap();
    send.write_all(&hdr_bytes).await.unwrap();
    send.write_all(&(1024u64).to_be_bytes()).await.unwrap();
    send.write_all(&[0x42u8; 1024]).await.unwrap();
    send.finish().unwrap();

    let (resp, _) =
        hephaestus_server::read_stream_message::<QuicResponse>(&mut recv, Duration::from_secs(5))
            .await
            .unwrap();
    assert!(matches!(resp, QuicResponse::Error { .. }));

    // Also test oversized PutBlob > MAX_QUIC_FRAME_BYTES fails via write_stream_message check.
    let mut dummy_send = conn.open_bi().await.unwrap().0;
    let oversized = vec![0u8; MAX_QUIC_FRAME_BYTES + 1];
    assert!(
        write_stream_message(
            &mut dummy_send,
            &QuicRequest::PutBlob {
                repo_id: RepoId::parse("sec/r").unwrap(),
                force_pack: false,
                payload: Vec::new(),
            },
            &oversized,
        )
        .await
        .is_err()
    );

    // Verified DR LTX restore rejects wrong digest and stale txid replay.
    let receipt1 = engine.ship_ltx_snapshot_manifest().await.unwrap();
    let receipt2 = engine.ship_ltx_snapshot_manifest().await.unwrap();
    let mut wrong_dig = receipt2.raw_digest;
    wrong_dig.0[0] ^= 0xFF;
    assert!(
        engine
            .restore_ltx_snapshot_verified(
                &receipt2.object_id,
                &dir.join("bad-dig.sqlite"),
                &wrong_dig,
                Some(&receipt2.snapshot_digest),
                Some(2),
            )
            .await
            .is_err()
    );
    assert!(
        engine
            .restore_ltx_snapshot_verified(
                &receipt2.object_id,
                &dir.join("ok-2.sqlite"),
                &receipt2.raw_digest,
                Some(&receipt2.snapshot_digest),
                Some(2),
            )
            .await
            .is_ok()
    );
    // Subsequent replay of snapshot 1 (< floor 2) must fail even with min_txid: None.
    assert!(
        engine
            .restore_ltx_snapshot_verified(
                &receipt1.object_id,
                &dir.join("replay-1.sqlite"),
                &receipt1.raw_digest,
                Some(&receipt1.snapshot_digest),
                None,
            )
            .await
            .is_err()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn json_payloads_reject_invalid_nested_identifiers() {
    use hephaestus_core::{DecisionDraft, ObservationDraft, ObservationFilter};
    let bad_dec = r#"{"decision_id":"D1","change_id":"../bad","op_id":"op1","author":"a","status":"accepted","rationale":"r","alternatives":[],"supersedes":null,"recorded_at_ms":1}"#;
    let bad_obs = r#"{"observation_id":"O1","kind":"test_receipt","change_id":"ch1","commit_id":"cm 1","op_id":"op1","producer":"a","passed":false,"summary":"s","payload_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"custody_uri":null,"metadata_json":"{}","recorded_at_ms":1}"#;
    assert!(serde_json::from_str::<DecisionDraft>(bad_dec).is_err());
    assert!(serde_json::from_str::<ObservationDraft>(bad_obs).is_err());
    assert!(serde_json::from_str::<ObservationFilter>(r#"{"op_id":"bad/op"}"#).is_err());
}
