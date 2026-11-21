//! Ed25519 mTLS-pinned `quinn 0.11` IPv6 QUIC client.

use crate::quic_proto::{QuicRequest, QuicResponse, read_stream_message, write_stream_message};
use crate::quic_tls::{QuicTlsIdentity, build_quinn_client_config};
use hephaestus_core::{
    ChangeId, DecisionDraft, DecisionRecord, ObservationDraft, ObservationFilter,
    ObservationRecord, RepoId,
};
use hephaestus_store::{CatalogStats, CommitRef};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Persistent Ed25519 mTLS-pinned QUIC client connecting over IPv6.
pub struct HephaestusQuicClient {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
}

impl HephaestusQuicClient {
    /// Connects over IPv6 UDP to `remote`, verifying `expected_server_fp` and presenting `client_id`.
    pub async fn connect(
        remote: SocketAddr,
        client_id: &QuicTlsIdentity,
        expected_server_fp: [u8; 32],
    ) -> Result<Self, String> {
        if !remote.is_ipv6() {
            return Err(format!(
                "HephaestusQuicClient requires IPv6 target, got {remote}"
            ));
        }
        let client_cfg = build_quinn_client_config(client_id, expected_server_fp)?;
        let bind_local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        let mut endpoint =
            quinn::Endpoint::client(bind_local).map_err(|e| format!("quic client bind: {e}"))?;
        endpoint.set_default_client_config(client_cfg);
        let connecting = endpoint
            .connect(remote, "hephaestus-node")
            .map_err(|e| format!("quic connect init: {e}"))?;
        let conn = connecting
            .await
            .map_err(|e| format!("quic mTLS handshake failed: {e}"))?;
        let client = Self {
            _endpoint: endpoint,
            conn,
        };
        // Wait for server acceptance of our client certificate (TLS 1.3 alert arrives post-1-RTT).
        client
            .health()
            .await
            .map_err(|e| format!("quic mTLS client verification failed: {e}"))?;
        Ok(client)
    }

    /// Executes a single typed request over a dedicated multiplexed bidirectional QUIC stream.
    pub async fn request(&self, req: QuicRequest) -> Result<QuicResponse, String> {
        let payload = match &req {
            QuicRequest::PutBlob { payload, .. } => payload.as_slice(),
            _ => &[],
        };
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| format!("quic open_bi: {e}"))?;
        write_stream_message(&mut send, &req, payload).await?;

        let (mut resp, body) =
            read_stream_message::<QuicResponse>(&mut recv, CLIENT_READ_TIMEOUT).await?;
        if let QuicResponse::BlobGet { payload: slot, .. } = &mut resp {
            *slot = body;
        }
        if let QuicResponse::Error { message } = resp {
            return Err(message);
        }
        Ok(resp)
    }

    /// Queries `/health` over QUIC.
    pub async fn health(&self) -> Result<(String, CatalogStats, usize), String> {
        match self.request(QuicRequest::Health).await? {
            QuicResponse::Health {
                backend,
                stats,
                pending_bytes,
            } => Ok((backend, stats, pending_bytes)),
            other => Err(format!("unexpected health response: {other:?}")),
        }
    }

    /// Stores a blob idempotently over QUIC, returning `(digest_hex, deduplicated)`.
    pub async fn put_blob(
        &self,
        repo_id: RepoId,
        payload: Vec<u8>,
        force_pack: bool,
    ) -> Result<(String, bool), String> {
        match self
            .request(QuicRequest::PutBlob {
                repo_id,
                force_pack,
                payload,
            })
            .await?
        {
            QuicResponse::BlobPut {
                digest_hex,
                deduplicated,
                ..
            } => Ok((digest_hex, deduplicated)),
            other => Err(format!("unexpected put_blob response: {other:?}")),
        }
    }

    /// Fetches a blob by BLAKE3 hex digest over QUIC.
    pub async fn get_blob(&self, digest_hex: &str) -> Result<Option<Vec<u8>>, String> {
        match self
            .request(QuicRequest::GetBlob {
                digest_hex: digest_hex.to_owned(),
            })
            .await?
        {
            QuicResponse::BlobGet { found, payload } => Ok(found.then_some(payload)),
            other => Err(format!("unexpected get_blob response: {other:?}")),
        }
    }

    /// Flushes staged blobs into a `GRNB0002` bundle over QUIC.
    pub async fn flush_bundle(&self) -> Result<Option<String>, String> {
        match self.request(QuicRequest::FlushBundle).await? {
            QuicResponse::Flushed { object_id } => Ok(object_id),
            other => Err(format!("unexpected flush response: {other:?}")),
        }
    }

    /// Replicates a [`CommitRef`] idempotently over QUIC, returning `(webhook_notified, deduplicated)`.
    pub async fn push_ref(&self, commit_ref: CommitRef) -> Result<(bool, bool), String> {
        match self.request(QuicRequest::PushRef { commit_ref }).await? {
            QuicResponse::RefPushed {
                webhook_notified,
                deduplicated,
                ..
            } => Ok((webhook_notified, deduplicated)),
            other => Err(format!("unexpected push_ref response: {other:?}")),
        }
    }

    /// Appends a Decision Log record idempotently over QUIC.
    pub async fn append_decision(
        &self,
        repo_id: RepoId,
        draft: DecisionDraft,
    ) -> Result<(DecisionRecord, bool), String> {
        match self
            .request(QuicRequest::AppendDecision { repo_id, draft })
            .await?
        {
            QuicResponse::DecisionAppended {
                record,
                deduplicated,
            } => Ok((record, deduplicated)),
            other => Err(format!("unexpected append_decision response: {other:?}")),
        }
    }

    /// Queries Decision Log records over QUIC.
    pub async fn query_decisions(
        &self,
        repo_id: RepoId,
        change_id: Option<ChangeId>,
    ) -> Result<Vec<DecisionRecord>, String> {
        match self
            .request(QuicRequest::QueryDecisions { repo_id, change_id })
            .await?
        {
            QuicResponse::Decisions { records } => Ok(records),
            other => Err(format!("unexpected query_decisions response: {other:?}")),
        }
    }

    /// Appends an Observation Log record idempotently over QUIC.
    pub async fn append_observation(
        &self,
        repo_id: RepoId,
        draft: ObservationDraft,
    ) -> Result<(ObservationRecord, bool), String> {
        match self
            .request(QuicRequest::AppendObservation { repo_id, draft })
            .await?
        {
            QuicResponse::ObservationAppended {
                record,
                deduplicated,
            } => Ok((record, deduplicated)),
            other => Err(format!("unexpected append_observation response: {other:?}")),
        }
    }

    /// Queries Observation Log records over QUIC.
    pub async fn query_observations(
        &self,
        repo_id: RepoId,
        filter: ObservationFilter,
    ) -> Result<Vec<ObservationRecord>, String> {
        match self
            .request(QuicRequest::QueryObservations { repo_id, filter })
            .await?
        {
            QuicResponse::Observations { records } => Ok(records),
            other => Err(format!("unexpected query_observations response: {other:?}")),
        }
    }
}
