//! Orthogonal append-only Observation Logs keyed by Jujutsu `(ChangeId, CommitId, OpId)`.

use crate::cas::BlobDigest;
use crate::decision_log::{ChainError, GENESIS_HASH, update_len_prefixed};
use crate::ids::{ChangeId, CommitId, OpId};
use crate::jcs::canonicalize_json;
use crate::mmr::Mmr;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Category of decoupled evidence attached to VCS history without rewriting commit hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// Test suite execution receipt.
    TestReceipt,
    /// Performance or workload benchmark receipt.
    Benchmark,
    /// Independent verifier pass/fail verdict.
    VerifierVerdict,
    /// External observability custody pointer (`o11y_custody_ref`).
    O11yCustodyRef,
    /// Agent execution trace reference.
    AgentTrace,
}

impl ObservationKind {
    /// Canonical lowercase representation used in persistence and hashing.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TestReceipt => "test_receipt",
            Self::Benchmark => "benchmark",
            Self::VerifierVerdict => "verifier_verdict",
            Self::O11yCustodyRef => "o11y_custody_ref",
            Self::AgentTrace => "agent_trace",
        }
    }

    /// Parses a canonical observation kind string.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "test_receipt" => Some(Self::TestReceipt),
            "benchmark" => Some(Self::Benchmark),
            "verifier_verdict" => Some(Self::VerifierVerdict),
            "o11y_custody_ref" => Some(Self::O11yCustodyRef),
            "agent_trace" => Some(Self::AgentTrace),
            _ => None,
        }
    }
}

/// Unchained input payload used to append a new [`ObservationRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationDraft {
    /// Stable observation identifier (e.g., `OBS-0001`).
    pub observation_id: String,
    /// Evidence stream category.
    pub kind: ObservationKind,
    /// Associated Jujutsu `ChangeId`.
    pub change_id: ChangeId,
    /// Associated Jujutsu `CommitId`.
    pub commit_id: CommitId,
    /// Associated Jujutsu `OpId`.
    pub op_id: OpId,
    /// Tool, CI runner, or verifier producing the observation.
    pub producer: String,
    /// Optional pass/fail outcome when applicable.
    pub passed: Option<bool>,
    /// Concise human-readable summary.
    pub summary: String,
    /// BLAKE3 digest of the external or CAS-stored evidence payload.
    pub payload_digest: BlobDigest,
    /// Optional custody URI pointing to external telemetry or artifact blob.
    pub custody_uri: Option<String>,
    /// Structured JSON metadata string (e.g., `"{}"`).
    pub metadata_json: String,
    /// Injected timestamp in milliseconds.
    pub recorded_at_ms: u64,
}

/// Immutable, hash-chained orthogonal Observation Log record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRecord {
    /// Zero-based monotonic sequence number inside the repository observation stream.
    pub seq: u64,
    /// Digest of the preceding [`ObservationRecord`], or [`GENESIS_HASH`] when `seq == 0`.
    pub prev_hash: BlobDigest,
    /// Domain-separated canonical BLAKE3 digest over `seq`, `prev_hash`, and all fields.
    pub record_hash: BlobDigest,
    /// Merkle Mountain Range root digest covering `0..=seq`.
    #[serde(default)]
    pub mmr_root: BlobDigest,
    /// Unique observation identifier within the repository.
    pub observation_id: String,
    /// Evidence stream category.
    pub kind: ObservationKind,
    /// Associated Jujutsu `ChangeId`.
    pub change_id: ChangeId,
    /// Associated Jujutsu `CommitId`.
    pub commit_id: CommitId,
    /// Associated Jujutsu `OpId`.
    pub op_id: OpId,
    /// Producing tool or verifier identity.
    pub producer: String,
    /// Optional pass/fail status.
    pub passed: Option<bool>,
    /// Concise summary.
    pub summary: String,
    /// Content digest of the detailed observation artifact.
    pub payload_digest: BlobDigest,
    /// Optional custody URI.
    pub custody_uri: Option<String>,
    /// Structured JSON metadata.
    pub metadata_json: String,
    /// Timestamp in milliseconds.
    pub recorded_at_ms: u64,
}

/// Query filter for orthogonal Observation Log lookups.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationFilter {
    /// Match a specific `ChangeId`.
    pub change_id: Option<ChangeId>,
    /// Match a specific `CommitId`.
    pub commit_id: Option<CommitId>,
    /// Match a specific `OpId`.
    pub op_id: Option<OpId>,
    /// Match a specific [`ObservationKind`].
    pub kind: Option<ObservationKind>,
    /// Match pass/fail status.
    pub passed: Option<bool>,
    /// Minimum inclusive sequence number (`seq >= since_seq`).
    #[serde(default)]
    pub since_seq: Option<u64>,
    /// Maximum number of matching records to return.
    #[serde(default)]
    pub limit: Option<usize>,
}

fn validate_observation_draft(draft: &ObservationDraft) -> Result<(), ChainError> {
    if draft.observation_id.trim().is_empty() {
        return Err(ChainError::EmptyField {
            field: "observation_id",
        });
    }
    if draft.producer.trim().is_empty() {
        return Err(ChainError::EmptyField { field: "producer" });
    }
    if draft.summary.trim().is_empty() {
        return Err(ChainError::EmptyField { field: "summary" });
    }
    if draft.metadata_json.trim().is_empty() {
        return Err(ChainError::EmptyField {
            field: "metadata_json",
        });
    }
    canonicalize_json(&draft.metadata_json).map_err(|e| ChainError::InvalidMetadataJson {
        detail: e.to_string(),
    })?;
    Ok(())
}

/// Computes the domain-separated canonical BLAKE3 digest for an [`ObservationRecord`].
#[must_use]
pub fn compute_observation_hash(
    seq: u64,
    prev_hash: BlobDigest,
    draft: &ObservationDraft,
) -> BlobDigest {
    let mut h = blake3::Hasher::new();
    h.update(b"hephaestus.observation.v1\0");
    h.update(&seq.to_le_bytes());
    h.update(prev_hash.as_bytes());
    update_len_prefixed(&mut h, draft.observation_id.as_bytes());
    update_len_prefixed(&mut h, draft.kind.as_str().as_bytes());
    update_len_prefixed(&mut h, draft.change_id.as_str().as_bytes());
    update_len_prefixed(&mut h, draft.commit_id.as_str().as_bytes());
    update_len_prefixed(&mut h, draft.op_id.as_str().as_bytes());
    update_len_prefixed(&mut h, draft.producer.as_bytes());
    match draft.passed {
        None => h.update(&[0u8]),
        Some(false) => h.update(&[1u8]),
        Some(true) => h.update(&[2u8]),
    };
    update_len_prefixed(&mut h, draft.summary.as_bytes());
    h.update(draft.payload_digest.as_bytes());
    match &draft.custody_uri {
        Some(uri) => {
            h.update(&[1u8]);
            update_len_prefixed(&mut h, uri.as_bytes());
        }
        None => {
            h.update(&[0u8]);
        }
    };
    let canonical_meta = canonicalize_json(&draft.metadata_json);
    let meta_bytes = match &canonical_meta {
        Ok(canon) => canon.as_bytes(),
        Err(_) => draft.metadata_json.as_bytes(),
    };
    update_len_prefixed(&mut h, meta_bytes);
    h.update(&draft.recorded_at_ms.to_le_bytes());
    BlobDigest(*h.finalize().as_bytes())
}

impl ObservationRecord {
    /// Extracts the underlying [`ObservationDraft`] fields for hash verification.
    #[must_use]
    pub fn as_draft(&self) -> ObservationDraft {
        ObservationDraft {
            observation_id: self.observation_id.clone(),
            kind: self.kind,
            change_id: self.change_id.clone(),
            commit_id: self.commit_id.clone(),
            op_id: self.op_id.clone(),
            producer: self.producer.clone(),
            passed: self.passed,
            summary: self.summary.clone(),
            payload_digest: self.payload_digest,
            custody_uri: self.custody_uri.clone(),
            metadata_json: self.metadata_json.clone(),
            recorded_at_ms: self.recorded_at_ms,
        }
    }

    /// Recomputes and returns the canonical BLAKE3 hash for this record.
    #[must_use]
    pub fn recompute_hash(&self) -> BlobDigest {
        compute_observation_hash(self.seq, self.prev_hash, &self.as_draft())
    }
}

/// Builds the Merkle Mountain Range over a sequence of [`ObservationRecord`] hashes.
#[must_use]
pub fn observation_chain_mmr(records: &[ObservationRecord]) -> Mmr {
    let mut mmr = Mmr::new();
    for rec in records {
        mmr.append(rec.record_hash);
    }
    mmr
}

/// Appends a validated, hash-chained [`ObservationRecord`] onto an in-memory observation chain.
pub fn append_observation_in_memory(
    chain: &mut Vec<ObservationRecord>,
    draft: ObservationDraft,
) -> Result<ObservationRecord, ChainError> {
    validate_observation_draft(&draft)?;
    if chain
        .iter()
        .any(|r| r.observation_id == draft.observation_id)
    {
        return Err(ChainError::DuplicateId {
            id: draft.observation_id,
        });
    }
    let (seq, prev_hash) = match chain.last() {
        Some(last) => (last.seq.saturating_add(1), last.record_hash),
        None => (0, GENESIS_HASH),
    };
    let record_hash = compute_observation_hash(seq, prev_hash, &draft);
    let mut mmr = observation_chain_mmr(chain);
    mmr.append(record_hash);
    let mmr_root = mmr.root();
    let rec = ObservationRecord {
        seq,
        prev_hash,
        record_hash,
        mmr_root,
        observation_id: draft.observation_id,
        kind: draft.kind,
        change_id: draft.change_id,
        commit_id: draft.commit_id,
        op_id: draft.op_id,
        producer: draft.producer,
        passed: draft.passed,
        summary: draft.summary,
        payload_digest: draft.payload_digest,
        custody_uri: draft.custody_uri,
        metadata_json: draft.metadata_json,
        recorded_at_ms: draft.recorded_at_ms,
    };
    chain.push(rec.clone());
    Ok(rec)
}

/// Returns `true` when `record` satisfies every populated predicate in `filter`.
#[must_use]
pub fn matches_observation_filter(record: &ObservationRecord, filter: &ObservationFilter) -> bool {
    filter
        .change_id
        .as_ref()
        .is_none_or(|c| &record.change_id == c)
        && filter
            .commit_id
            .as_ref()
            .is_none_or(|c| &record.commit_id == c)
        && filter.op_id.as_ref().is_none_or(|o| &record.op_id == o)
        && filter.kind.is_none_or(|k| record.kind == k)
        && filter.passed.is_none_or(|p| record.passed == Some(p))
        && filter.since_seq.is_none_or(|s| record.seq >= s)
}

/// Verifies contiguous sequence numbers, `prev_hash` linkage, uniqueness, BLAKE3 digests, and MMR roots.
pub fn verify_observation_chain(records: &[ObservationRecord]) -> Result<(), ChainError> {
    let mut expected_prev = GENESIS_HASH;
    let mut seen_ids = BTreeSet::new();
    let mut mmr = Mmr::new();
    for (idx, rec) in records.iter().enumerate() {
        let expected_seq = idx as u64;
        if rec.seq != expected_seq {
            return Err(ChainError::NonMonotonicSeq {
                index: idx,
                expected: expected_seq,
                actual: rec.seq,
            });
        }
        if rec.prev_hash != expected_prev {
            return Err(ChainError::PrevHashMismatch { seq: rec.seq });
        }
        let draft = rec.as_draft();
        validate_observation_draft(&draft)?;
        if !seen_ids.insert(rec.observation_id.clone()) {
            return Err(ChainError::DuplicateId {
                id: rec.observation_id.clone(),
            });
        }
        if rec.record_hash != compute_observation_hash(rec.seq, rec.prev_hash, &draft) {
            return Err(ChainError::RecordHashMismatch { seq: rec.seq });
        }
        mmr.append(rec.record_hash);
        if rec.mmr_root != mmr.root() {
            return Err(ChainError::MmrRootMismatch { seq: rec.seq });
        }
        expected_prev = rec.record_hash;
    }
    Ok(())
}
