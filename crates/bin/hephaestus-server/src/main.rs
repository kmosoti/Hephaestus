#![forbid(unsafe_code)]
//! Pure-IPv6 Hephaestus daemon exposing Ed25519 mTLS QUIC + authenticated HTTP/1.1
//! compatibility bridge and verified `"LTX1"` snapshot shipping/restore.

use hephaestus_core::{BlobDigest, SecretString, decode_hex};
use hephaestus_jj::JjRepoService;
use hephaestus_server::{
    HephaestusEngine, HephaestusQuicServer, HttpAuthMode, HttpBridgeConfig, QuicTlsIdentity,
    build_http_router_with_config, load_http_auth_token_hash, spawn_ltx_shipper,
};
use hephaestus_store::{ObjectBackend, WebhookSink};
use hephaestus_store_object::{
    DriveHttpClient, GOOGLE_DRIVE_BASE_URL, GoogleDriveStore, HttpWebhookSink, NoopWebhookSink,
    ObjectStoreBackend, ObjectStoreConfig, PackedCasEngine,
};
use hephaestus_store_sqlite::{SqliteStore, restore_ltx_snapshot_zstd_verified};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

fn load_server_identity(
    tls_key_path: Option<&PathBuf>,
    data_dir: &std::path::Path,
    dev_ephemeral: bool,
) -> Result<QuicTlsIdentity, Box<dyn std::error::Error>> {
    if let Some(path) = tls_key_path {
        return Ok(QuicTlsIdentity::load_or_generate(path, "hephaestus-node")?);
    }
    if let Some(cred_dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let cred_file = PathBuf::from(cred_dir).join("tls-ed25519.pem");
        if cred_file.exists() {
            let pem = std::fs::read_to_string(&cred_file)?;
            return Ok(QuicTlsIdentity::from_key_pem(&pem, "hephaestus-node")?);
        }
    }
    if dev_ephemeral {
        return Ok(QuicTlsIdentity::generate("hephaestus-node")?);
    }
    let default_path = data_dir.join("tls-ed25519.pem");
    Ok(QuicTlsIdentity::load_or_generate(
        &default_path,
        "hephaestus-node",
    )?)
}

fn next_flag_value(
    args: &mut std::iter::Skip<std::env::Args>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn resolve_http_auth(
    http_addr: SocketAddr,
    token_file: Option<&PathBuf>,
    allow_unauth_loopback: bool,
) -> Result<HttpAuthMode, Box<dyn std::error::Error>> {
    if let Some(path) = token_file {
        if allow_unauth_loopback {
            return Err(
                "cannot combine --http-auth-token-file with --allow-unauthenticated-loopback-http"
                    .into(),
            );
        }
        let hash = load_http_auth_token_hash(path)?;
        return Ok(HttpAuthMode::BearerSha256(hash));
    }
    if !http_addr.ip().is_loopback() {
        return Err("refusing non-loopback --http-bind without --http-auth-token-file".into());
    }
    if !allow_unauth_loopback {
        return Err(
            "HTTP bridge requires --http-auth-token-file (or explicit --allow-unauthenticated-loopback-http for loopback testing)"
                .into(),
        );
    }
    Ok(HttpAuthMode::AllowUnauthenticatedLoopback)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut http_bind = "[::1]:8081".to_owned();
    let mut quic_bind = "[::1]:8443".to_owned();
    let mut data_dir = PathBuf::from("./hephaestus-data");
    let mut object_uri: Option<String> = None;
    let mut drive_url: Option<String> = None;
    let mut webhook_url: Option<String> = None;
    let mut jj_repo: Option<PathBuf> = None;
    let mut tls_key_path: Option<PathBuf> = None;
    let mut http_auth_token_file: Option<PathBuf> = None;
    let mut allow_unauthenticated_loopback_http = false;
    let mut allow_client_fps: Vec<[u8; 32]> = Vec::new();
    let mut dev_ephemeral = false;
    let mut ltx_interval_secs: u64 = 300;
    let mut restore_ltx_object: Option<String> = None;
    let mut restore_ltx_digest: Option<BlobDigest> = None;
    let mut restore_ltx_min_txid: Option<u64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--http-bind" => http_bind = next_flag_value(&mut args, "--http-bind")?,
            "--quic-bind" => quic_bind = next_flag_value(&mut args, "--quic-bind")?,
            "--data-dir" => data_dir = PathBuf::from(next_flag_value(&mut args, "--data-dir")?),
            "--object-uri" => object_uri = Some(next_flag_value(&mut args, "--object-uri")?),
            "--drive-url" => drive_url = Some(next_flag_value(&mut args, "--drive-url")?),
            "--webhook-url" => webhook_url = Some(next_flag_value(&mut args, "--webhook-url")?),
            "--jj-repo" => jj_repo = Some(PathBuf::from(next_flag_value(&mut args, "--jj-repo")?)),
            "--tls-key-path" => {
                tls_key_path = Some(PathBuf::from(next_flag_value(&mut args, "--tls-key-path")?));
            }
            "--http-auth-token-file" => {
                http_auth_token_file = Some(PathBuf::from(next_flag_value(
                    &mut args,
                    "--http-auth-token-file",
                )?));
            }
            "--allow-unauthenticated-loopback-http" => {
                allow_unauthenticated_loopback_http = true;
            }
            "--dev-ephemeral" => dev_ephemeral = true,
            "--ltx-interval-secs" => {
                ltx_interval_secs = next_flag_value(&mut args, "--ltx-interval-secs")?.parse()?;
            }
            "--allow-client-fp" => {
                let hex_fp = next_flag_value(&mut args, "--allow-client-fp")?;
                allow_client_fps.push(decode_hex(&hex_fp)?);
            }
            "--restore-ltx-object" => {
                restore_ltx_object = Some(next_flag_value(&mut args, "--restore-ltx-object")?);
            }
            "--restore-ltx-digest" => {
                let hex_dig = next_flag_value(&mut args, "--restore-ltx-digest")?;
                restore_ltx_digest = Some(BlobDigest::from_hex(&hex_dig)?);
            }
            "--restore-ltx-min-txid" => {
                restore_ltx_min_txid =
                    Some(next_flag_value(&mut args, "--restore-ltx-min-txid")?.parse()?);
            }
            "--help" | "-h" => {
                println!(
                    "hephaestus-server [--http-bind [::1]:8081] [--quic-bind [::1]:8443] \
                     [--data-dir DIR] [--object-uri file://DIR|s3://...|gs://...|memory://] \
                     [--drive-url URL] [--webhook-url URL] [--jj-repo DIR] \
                     [--tls-key-path PEM] [--http-auth-token-file PATH] \
                     [--allow-unauthenticated-loopback-http] [--ltx-interval-secs SECS] \
                     [--allow-client-fp HEX] [--dev-ephemeral] \
                     [--restore-ltx-object OID --restore-ltx-digest HEX [--restore-ltx-min-txid N]]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown flag `{other}`").into()),
        }
    }

    let http_addr: SocketAddr = http_bind.parse()?;
    let quic_addr: SocketAddr = quic_bind.parse()?;
    if !http_addr.is_ipv6() || !quic_addr.is_ipv6() {
        return Err("hephaestus-server enforces pure-IPv6 bind addresses (e.g. [::1]:8081)".into());
    }
    let http_auth = resolve_http_auth(
        http_addr,
        http_auth_token_file.as_ref(),
        allow_unauthenticated_loopback_http,
    )?;

    std::fs::create_dir_all(&data_dir)?;
    let server_id = load_server_identity(tls_key_path.as_ref(), &data_dir, dev_ephemeral)?;
    if allow_client_fps.is_empty() {
        if dev_ephemeral {
            allow_client_fps.push(server_id.fingerprint);
        } else {
            return Err(
                "at least one --allow-client-fp SPKI SHA-256 hex pin is required (or pass --dev-ephemeral for local development)"
                    .into(),
            );
        }
    }

    let backend: Arc<dyn ObjectBackend> = if let Some(durl) = drive_url {
        let token = std::env::var_os("CREDENTIALS_DIRECTORY")
            .and_then(|dir| {
                std::fs::read_to_string(PathBuf::from(dir).join("drive-access-token")).ok()
            })
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        let client = DriveHttpClient::new(
            if durl.is_empty() {
                GOOGLE_DRIVE_BASE_URL.to_owned()
            } else {
                durl
            },
            SecretString::new(token),
        )?;
        Arc::new(GoogleDriveStore::new(client, 1))
    } else {
        let cfg = match object_uri {
            Some(uri) => ObjectStoreConfig::from_uri(&uri)?,
            None => ObjectStoreConfig::LocalFs {
                root: data_dir.join("objects"),
                prefix: String::new(),
            },
        };
        Arc::new(ObjectStoreBackend::from_config(&cfg)?)
    };

    let db_path = data_dir.join("catalog.sqlite");
    let sqlite = match restore_ltx_object {
        Some(obj_id) => {
            let expected_digest = restore_ltx_digest
                .ok_or("--restore-ltx-object requires --restore-ltx-digest <64-hex-blake3>")?;
            let snap_bytes = backend.get_bundle(&obj_id).await?;
            let dest = db_path.clone();
            tokio::task::spawn_blocking(move || {
                restore_ltx_snapshot_zstd_verified(
                    &snap_bytes,
                    &dest,
                    &expected_digest,
                    restore_ltx_min_txid,
                )
            })
            .await??
        }
        None => SqliteStore::open(&db_path)?,
    };

    let cas = PackedCasEngine::new(Arc::new(sqlite.clone()), backend, 4 * 1024 * 1024);
    let webhook: Arc<dyn WebhookSink> = match webhook_url {
        Some(url) => Arc::new(HttpWebhookSink::new(url)?),
        None => Arc::new(NoopWebhookSink),
    };
    let jj_service = JjRepoService::new("Hephaestus Server", "hephaestus@example.invalid")?;
    let engine = Arc::new(HephaestusEngine::new(
        sqlite, cas, webhook, jj_service, jj_repo,
    ));

    let _ltx_task = (ltx_interval_secs > 0)
        .then(|| spawn_ltx_shipper(Arc::clone(&engine), Duration::from_secs(ltx_interval_secs)));

    let quic_srv = HephaestusQuicServer::bind(quic_addr, server_id, allow_client_fps)?;
    let http_listener = TcpListener::bind(http_addr).await?;
    let http_router = build_http_router_with_config(
        Arc::clone(&engine),
        HttpBridgeConfig {
            auth: http_auth,
            ..HttpBridgeConfig::default()
        },
    );

    println!(
        "hephaestus-server listening: http={} quic={} quic_fp={}",
        http_listener.local_addr()?,
        quic_srv.local_addr(),
        quic_srv.identity().fingerprint_hex
    );

    let quic_engine = Arc::clone(&engine);
    tokio::select! {
        res = axum::serve(http_listener, http_router) => {
            res?;
        }
        () = quic_srv.serve(quic_engine) => {}
    }
    Ok(())
}
