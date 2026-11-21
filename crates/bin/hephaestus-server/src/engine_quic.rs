//! QUIC request dispatch over [`HephaestusEngine`].

use crate::engine::HephaestusEngine;
use crate::quic_proto::{QuicRequest, QuicResponse};
use hephaestus_store::StoreError;

impl HephaestusEngine {
    /// Dispatches one decoded QUIC stream request against [`HephaestusEngine`].
    pub async fn handle_quic(&self, req: QuicRequest) -> QuicResponse {
        match self.dispatch_quic(req).await {
            Ok(resp) => resp,
            Err(err) => QuicResponse::Error {
                message: err.to_string(),
            },
        }
    }

    async fn dispatch_quic(&self, req: QuicRequest) -> Result<QuicResponse, StoreError> {
        match req {
            QuicRequest::Health => {
                let (stats, pending_bytes) = self.stats().await?;
                Ok(QuicResponse::Health {
                    backend: self.backend_kind().to_owned(),
                    stats,
                    pending_bytes,
                })
            }
            QuicRequest::PutBlob {
                repo_id,
                force_pack,
                payload,
            } => {
                let len = payload.len();
                let (digest, deduplicated) = self
                    .put_blob_idempotent(&repo_id, payload, force_pack)
                    .await?;
                Ok(QuicResponse::BlobPut {
                    digest_hex: digest.to_hex(),
                    bytes: len,
                    deduplicated,
                })
            }
            QuicRequest::GetBlob { digest_hex } => match self.get_blob_hex(&digest_hex).await? {
                Some(payload) => Ok(QuicResponse::BlobGet {
                    found: true,
                    payload,
                }),
                None => Ok(QuicResponse::BlobGet {
                    found: false,
                    payload: Vec::new(),
                }),
            },
            QuicRequest::FlushBundle => {
                let object_id = self.flush_bundle().await?;
                Ok(QuicResponse::Flushed { object_id })
            }
            QuicRequest::PushRef { commit_ref } => {
                let (webhook_notified, deduplicated) =
                    self.push_ref_idempotent(&commit_ref).await?;
                Ok(QuicResponse::RefPushed {
                    accepted: true,
                    webhook_notified,
                    deduplicated,
                })
            }
            QuicRequest::ListRefs { repo_id } => {
                let refs = self.list_refs(&repo_id).await?;
                Ok(QuicResponse::Refs { refs })
            }
            QuicRequest::AppendDecision { repo_id, draft } => {
                let (record, deduplicated) =
                    self.append_decision_idempotent(&repo_id, draft).await?;
                Ok(QuicResponse::DecisionAppended {
                    record,
                    deduplicated,
                })
            }
            QuicRequest::QueryDecisions { repo_id, change_id } => {
                let records = self.list_decisions(&repo_id, change_id.as_ref()).await?;
                Ok(QuicResponse::Decisions { records })
            }
            QuicRequest::VerifyDecisions { repo_id } => {
                let verified_count = self.verify_decisions(&repo_id).await?;
                Ok(QuicResponse::Verified { verified_count })
            }
            QuicRequest::AppendObservation { repo_id, draft } => {
                let (record, deduplicated) =
                    self.append_observation_idempotent(&repo_id, draft).await?;
                Ok(QuicResponse::ObservationAppended {
                    record,
                    deduplicated,
                })
            }
            QuicRequest::QueryObservations { repo_id, filter } => {
                let records = self.query_observations(&repo_id, &filter).await?;
                Ok(QuicResponse::Observations { records })
            }
            QuicRequest::VerifyObservations { repo_id } => {
                let verified_count = self.verify_observations(&repo_id).await?;
                Ok(QuicResponse::Verified { verified_count })
            }
            QuicRequest::JjListOps { limit } => {
                let ops = self.list_jj_ops(limit).await?;
                Ok(QuicResponse::JjOps { ops })
            }
        }
    }
}
