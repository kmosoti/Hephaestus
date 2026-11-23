#![forbid(unsafe_code)]
//! Pure-IPv6 Hephaestus server library exposing Ed25519 mTLS QUIC, HTTP/1.1 REST,
//! streaming multi-repo Git smart-HTTP bridge, and background `"LTX1"` snapshot shipping.

pub mod engine;
mod engine_ltx;
mod engine_quic;
mod error_map;
pub mod http;
pub mod http_auth;
mod http_git;
mod http_git_io;
pub mod http_types;
pub mod quic_client;
pub mod quic_io;
pub mod quic_proto;
pub mod quic_server;
mod quic_spki;
pub mod quic_tls;

pub use engine::{HephaestusEngine, spawn_ltx_shipper, validate_git_repo_segment};
pub use engine_ltx::LtxSnapshotReceipt;
pub use http::{build_authenticated_http_router, build_http_router, build_http_router_with_config};
pub use http_auth::{HttpAuthMode, MAX_HTTP_AUTH_TOKEN_FILE_BYTES, load_http_auth_token_hash};
pub use http_types::{
    DEFAULT_HTTP_MAX_CONCURRENCY, DEFAULT_HTTP_REQUEST_TIMEOUT, DEFAULT_MAX_GIT_CHILDREN,
    HttpBridgeConfig, MAX_HTTP_BODY_BYTES,
};
pub use quic_client::HephaestusQuicClient;
pub use quic_io::{
    QuicMessageMeta, read_stream_message, read_stream_message_budgeted, write_stream_message,
};
pub use quic_proto::{
    DEFAULT_QUIC_STREAM_DEADLINE, MAX_QUIC_FRAME_BYTES, MAX_QUIC_HEADER_BYTES,
    QUIC_STREAM_CHUNK_BYTES, QuicRequest, QuicResponse, QuicStreamOp,
};
pub use quic_server::{
    DEFAULT_MAX_CONCURRENT_QUIC_CONNECTIONS, DEFAULT_MAX_CONCURRENT_QUIC_STREAMS,
    DEFAULT_MAX_QUIC_INFLIGHT_BYTES, DEFAULT_QUIC_READ_TIMEOUT, HephaestusQuicServer,
};
pub use quic_tls::{
    ALPN_HEPHAESTUS_QUIC, QuicTlsIdentity, build_quinn_client_config, build_quinn_server_config,
    ct_eq_32, extract_spki_der, spki_sha256_pin,
};
