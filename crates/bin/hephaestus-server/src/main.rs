#![forbid(unsafe_code)]
//! Pure-IPv6 Hephaestus daemon exposing Ed25519 mTLS QUIC + HTTP/1.1 compatibility bridge
//! and periodic `"LTX1"` snapshot shipping.

use hephaestus_core::{SecretString, decode_hex};
use hephaestus_jj::JjRepoService;
use hephaestus_server::{
    HephaestusEngine, HephaestusQuicServer, QuicTlsIdentity, build_http_router, spawn_ltx_shipper,
};
use hephaestus_store::{ObjectBackend, WebhookSink};
use hephaestus_store_object::{
    DriveHttpClient, GOOGLE_DRIVE_BASE_URL, GoogleDriveStore, HttpWebhookSink, NoopWebhookSink,
    ObjectStoreBackend, ObjectStoreConfig, PackedCasEngine,
};
use hephaestus_store_sqlite::SqliteStore;
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
    let mut allow_client_fps: Vec<[u8; 32]> = Vec::new();
    let mut dev_ephemeral = false;
    let mut ltx_interval_secs: u64 = 300;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--http-bind" => {
                if let Some(v) = args.next() {
                    http_bind = v;
                }
            }
            "--quic-bind" => {
                if let Some(v) = args.next() {
                    quic_bind = v;
                }
            }
            "--data-dir" => {
                if let Some(v) = args.next() {
                    data_dir = PathBuf::from(v);
                }
            }
            "--object-uri" => object_uri = args.next(),
            "--drive-url" => drive_url = args.next(),
            "--webhook-url" => webhook_url = args.next(),
            "--jj-repo" => jj_repo = args.next().map(PathBuf::from),
            "--tls-key-path" => tls_key_path = args.next().map(PathBuf::from),
            "--dev-ephemeral" => dev_ephemeral = true,
            "--ltx-interval-secs" => {
                if let Some(v) = args.next() {
                    ltx_interval_secs = v.parse()?;
                }
            }
            "--allow-client-fp" => {
                if let Some(hex_fp) = args.next() {
                    allow_client_fps.push(decode_hex(&hex_fp)?);
                }
            }
            "--help" | "-h" => {
                println!(
                    "hephaestus-server [--http-bind [::1]:8081] [--quic-bind [::1]:8443] \
                     [--data-dir DIR] [--object-uri file://DIR|s3://...|gs://...|memory://] \
                     [--drive-url URL] [--webhook-url URL] [--jj-repo DIR] \
                     [--tls-key-path PEM] [--ltx-interval-secs SECS] \
                     [--allow-client-fp HEX] [--dev-ephemeral]"
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

    let sqlite = SqliteStore::open(data_dir.join("catalog.sqlite"))?;
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

    println!(
        "hephaestus-server listening: http={} quic={} quic_fp={}",
        http_listener.local_addr()?,
        quic_srv.local_addr(),
        quic_srv.identity().fingerprint_hex
    );

    let quic_engine = Arc::clone(&engine);
    tokio::select! {
        res = axum::serve(http_listener, build_http_router(engine)) => {
            res?;
        }
        () = quic_srv.serve(quic_engine) => {}
    }
    Ok(())
}
