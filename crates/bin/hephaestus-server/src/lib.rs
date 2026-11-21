#![forbid(unsafe_code)]
//! Pure-IPv6 Hephaestus server library exposing Ed25519 mTLS QUIC, HTTP/1.1 REST,
//! streaming multi-repo Git smart-HTTP bridge, and background `"LTX1"` snapshot shipping.

pub mod engine;
mod engine_quic;
pub mod http;
mod http_git;
pub mod quic_client;
pub mod quic_proto;
pub mod quic_server;
mod quic_spki;
pub mod quic_tls;

pub use engine::{HephaestusEngine, spawn_ltx_shipper, validate_git_repo_segment};
pub use http::build_http_router;
pub use quic_client::HephaestusQuicClient;
pub use quic_proto::{
    MAX_QUIC_FRAME_BYTES, MAX_QUIC_HEADER_BYTES, QUIC_STREAM_CHUNK_BYTES, QuicRequest,
    QuicResponse, QuicStreamOp, read_stream_message, write_stream_message,
};
pub use quic_server::{
    DEFAULT_MAX_CONCURRENT_QUIC_STREAMS, DEFAULT_QUIC_READ_TIMEOUT, HephaestusQuicServer,
};
pub use quic_tls::{
    ALPN_HEPHAESTUS_QUIC, QuicTlsIdentity, build_quinn_client_config, build_quinn_server_config,
    ct_eq_32, extract_spki_der, spki_sha256_pin,
};
