//! Pure-IPv6 Ed25519 mTLS-pinned `quinn` QUIC server with bounded connections,
//! weighted payload memory admission, per-chunk timeouts, and absolute stream deadlines.

use crate::engine::HephaestusEngine;
use crate::error_map::sanitize_quic_error;
use crate::quic_io::{read_stream_message_budgeted, write_stream_message};
use crate::quic_proto::{DEFAULT_QUIC_STREAM_DEADLINE, QuicRequest, QuicResponse};
use crate::quic_tls::{QuicTlsIdentity, build_quinn_server_config};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Default maximum concurrent bidirectional QUIC streams processed across all peers.
pub const DEFAULT_MAX_CONCURRENT_QUIC_STREAMS: usize = 256;
/// Default maximum concurrent QUIC peer connections.
pub const DEFAULT_MAX_CONCURRENT_QUIC_CONNECTIONS: usize = 128;
/// Default weighted aggregate inflight QUIC payload byte budget (64 MiB).
pub const DEFAULT_MAX_QUIC_INFLIGHT_BYTES: usize = 64 * 1024 * 1024;
/// Default per-chunk read timeout guarding against slowloris or stalled peers.
pub const DEFAULT_QUIC_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Multiplexed QUIC server backed by `quinn 0.11` over IPv6 UDP.
pub struct HephaestusQuicServer {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    identity: QuicTlsIdentity,
    max_concurrent_streams: usize,
    max_concurrent_connections: usize,
    max_inflight_bytes: usize,
    stream_read_timeout: Duration,
    stream_deadline: Duration,
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
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_QUIC_CONNECTIONS,
            max_inflight_bytes: DEFAULT_MAX_QUIC_INFLIGHT_BYTES,
            stream_read_timeout: DEFAULT_QUIC_READ_TIMEOUT,
            stream_deadline: DEFAULT_QUIC_STREAM_DEADLINE,
        })
    }

    /// Configures maximum concurrent streams and per-chunk read timeout.
    #[must_use]
    pub fn with_limits(mut self, max_concurrent_streams: usize, read_timeout: Duration) -> Self {
        self.max_concurrent_streams = max_concurrent_streams.max(1);
        self.stream_read_timeout = read_timeout;
        self
    }

    /// Configures aggregate weighted payload memory budget and absolute per-stream deadline.
    #[must_use]
    pub fn with_memory_budget(
        mut self,
        max_inflight_bytes: usize,
        stream_deadline: Duration,
    ) -> Self {
        self.max_inflight_bytes = max_inflight_bytes.max(1024);
        self.stream_deadline = stream_deadline;
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
        let stream_sem = Arc::new(Semaphore::new(self.max_concurrent_streams));
        let conn_sem = Arc::new(Semaphore::new(self.max_concurrent_connections));
        let byte_budget = Arc::new(Semaphore::new(self.max_inflight_bytes));
        let read_timeout = self.stream_read_timeout;
        let stream_deadline = self.stream_deadline;
        while let Some(incoming) = self.endpoint.accept().await {
            let Ok(conn_permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                drop(incoming);
                continue;
            };
            let eng = Arc::clone(&engine);
            let sem_conn = Arc::clone(&stream_sem);
            let budget_conn = Arc::clone(&byte_budget);
            tokio::spawn(async move {
                let _conn_permit = conn_permit;
                let Ok(conn) = incoming.await else {
                    return;
                };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(permit) = Arc::clone(&sem_conn).acquire_owned().await else {
                        break;
                    };
                    let eng_stream = Arc::clone(&eng);
                    let budget_stream = Arc::clone(&budget_conn);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let (resp, _byte_permit) =
                            match read_stream_message_budgeted::<QuicRequest>(
                                &mut recv,
                                read_timeout,
                                stream_deadline,
                                Some(&budget_stream),
                            )
                            .await
                            {
                                Ok((mut req, payload, byte_permit)) => {
                                    if let QuicRequest::PutBlob { payload: slot, .. } = &mut req {
                                        *slot = payload;
                                    }
                                    (eng_stream.handle_quic(req).await, byte_permit)
                                }
                                Err(msg) => (
                                    QuicResponse::Error {
                                        message: sanitize_quic_error(
                                            "invalid or timed-out QUIC request",
                                            &msg,
                                        ),
                                    },
                                    None,
                                ),
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
