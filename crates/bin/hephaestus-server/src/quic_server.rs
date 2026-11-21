//! Pure-IPv6 Ed25519 mTLS-pinned `quinn` QUIC server with bounded concurrency and chunked streaming.

use crate::engine::HephaestusEngine;
use crate::quic_proto::{QuicRequest, QuicResponse, read_stream_message, write_stream_message};
use crate::quic_tls::{QuicTlsIdentity, build_quinn_server_config};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Default maximum concurrent bidirectional QUIC streams processed across all peers.
pub const DEFAULT_MAX_CONCURRENT_QUIC_STREAMS: usize = 256;
/// Default per-chunk read timeout guarding against slowloris or stalled peers.
pub const DEFAULT_QUIC_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Multiplexed QUIC server backed by `quinn 0.11` over IPv6 UDP.
pub struct HephaestusQuicServer {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    identity: QuicTlsIdentity,
    max_concurrent_streams: usize,
    stream_read_timeout: Duration,
}

impl HephaestusQuicServer {
    /// Binds an Ed25519 mTLS-pinned QUIC endpoint on `bind_addr` (must be IPv6).
    pub fn bind(
        bind_addr: SocketAddr,
        identity: QuicTlsIdentity,
        allowed_client_fps: Vec<[u8; 32]>,
    ) -> Result<Self, String> {
        if !bind_addr.is_ipv6() {
            return Err(format!(
                "hephaestus-server QUIC requires an IPv6 bind address, got {bind_addr}"
            ));
        }
        let server_cfg = build_quinn_server_config(&identity, allowed_client_fps)?;
        let endpoint = quinn::Endpoint::server(server_cfg, bind_addr)
            .map_err(|e| format!("quinn endpoint bind {bind_addr}: {e}"))?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| format!("quinn local_addr: {e}"))?;
        Ok(Self {
            endpoint,
            local_addr,
            identity,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_QUIC_STREAMS,
            stream_read_timeout: DEFAULT_QUIC_READ_TIMEOUT,
        })
    }

    /// Configures maximum concurrent streams and per-chunk read timeout.
    #[must_use]
    pub fn with_limits(mut self, max_concurrent_streams: usize, read_timeout: Duration) -> Self {
        self.max_concurrent_streams = max_concurrent_streams.max(1);
        self.stream_read_timeout = read_timeout;
        self
    }

    /// Returns the bound IPv6 UDP socket address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the server's Ed25519 certificate identity and SPKI SHA-256 pin.
    #[must_use]
    pub const fn identity(&self) -> &QuicTlsIdentity {
        &self.identity
    }

    /// Serves incoming mTLS-authenticated QUIC connections and multiplexed streams until closed.
    pub async fn serve(self, engine: Arc<HephaestusEngine>) {
        let sem = Arc::new(Semaphore::new(self.max_concurrent_streams));
        let timeout = self.stream_read_timeout;
        while let Some(incoming) = self.endpoint.accept().await {
            let eng = Arc::clone(&engine);
            let sem_conn = Arc::clone(&sem);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else {
                    return;
                };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(permit) = Arc::clone(&sem_conn).acquire_owned().await else {
                        break;
                    };
                    let eng_stream = Arc::clone(&eng);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let resp =
                            match read_stream_message::<QuicRequest>(&mut recv, timeout).await {
                                Ok((mut req, payload)) => {
                                    if let QuicRequest::PutBlob { payload: slot, .. } = &mut req {
                                        *slot = payload;
                                    }
                                    eng_stream.handle_quic(req).await
                                }
                                Err(msg) => QuicResponse::Error { message: msg },
                            };
                        let payload = match &resp {
                            QuicResponse::BlobGet { payload, .. } => payload.as_slice(),
                            _ => &[],
                        };
                        let _ = write_stream_message(&mut send, &resp, payload).await;
                    });
                }
            });
        }
    }
}
