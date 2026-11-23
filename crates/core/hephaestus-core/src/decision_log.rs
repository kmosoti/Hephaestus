//! Hash-chained Decision Log records keyed by Jujutsu `ChangeId` and `OpId`.

use crate::cas::BlobDigest;
use crate::chain_verify::DecisionChainVerifier;
use crate::ids::{ChangeId, OpId};
use crate::mmr::Mmr;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Genesis predecessor digest for sequence `0` in a decision or observation chain.
pub const GENESIS_HASH: BlobDigest = BlobDigest([0u8; 32]);

/// Lifecycle state of a recorded architectural or operational decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    /// Drafted and awaiting confirmation.
    Proposed,
    /// Ratified and active for the referenced `ChangeId`.
    Accepted,
    /// Replaced by a newer decision record.
    Superseded,
    /// Explicitly declined after review.
    Rejected,
}

impl DecisionStatus {
    /// Canonical lowercase representation used in persistence and canonical hashing.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }

    /// Parses a canonical decision status string.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "proposed" => Some(Self::Proposed),
            "accepted" => Some(Self::Accepted),
            "superseded" => Some(Self::Superseded),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// Unchained input payload used to append a new [`DecisionRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionDraft {
    /// Stable identifier (e.g., `DEC-0001`).
    pub decision_id: String,
    /// Associated Jujutsu `ChangeId`.
    pub change_id: ChangeId,
    /// Jujutsu `OpId` active when the decision was recorded.
    pub op_id: OpId,
    /// Author or agent identity recording the decision.
    pub author: String,
    /// Lifecycle status.
    pub status: DecisionStatus,
    /// Concise rationale explaining why this choice was made.
    pub rationale: String,
    /// Alternatives considered and rejected.
    pub alternatives: Vec<String>,
    /// Optional earlier `decision_id` superseded by this record.
    pub supersedes: Option<String>,
    /// Injected monotonic/epoch timestamp in milliseconds.
    pub recorded_at_ms: u64,
}

/// Immutable, hash-chained Decision Log entry keyed to `jj` change and operation IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// Zero-based monotonic sequence number inside the repository decision stream.
    pub seq: u64,
    /// Digest of the preceding [`DecisionRecord`], or [`GENESIS_HASH`] when `seq == 0`.
    pub prev_hash: BlobDigest,
    /// Domain-separated canonical BLAKE3 digest over `seq`, `prev_hash`, and all fields.
    pub record_hash: BlobDigest,
    /// Merkle Mountain Range root digest covering `0..=seq`.
    #[serde(default)]
    pub mmr_root: BlobDigest,
    /// Unique decision identifier within the repository.
    pub decision_id: String,
    /// Associated Jujutsu `ChangeId`.
    pub change_id: ChangeId,
    /// Jujutsu `OpId` at record time.
    pub op_id: OpId,
    /// Author or agent identity.
    pub author: String,
    /// Decision lifecycle state.
    pub status: DecisionStatus,
    /// Decision rationale.
    pub rationale: String,
    /// Considered alternatives.
    pub alternatives: Vec<String>,
    /// Superseded `decision_id`, if any.
    pub supersedes: Option<String>,
    /// Timestamp in milliseconds.
    pub recorded_at_ms: u64,
}

/// Verification failures for hash-chained Decision Log and Observation Log streams.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChainError {
    /// Required text field was empty or whitespace-only.
    #[error("required field `{field}` must not be empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// Duplicate `decision_id` or `observation_id` in the same repository stream.
    #[error("duplicate log record identifier `{id}`")]
    DuplicateId {
        /// Conflicting record ID.
        id: String,
    },
    /// `supersedes` referenced an unknown or forward decision identifier.
    #[error("decision `{decision_id}` supersedes unknown prior decision `{target}`")]
    UnknownSupersedes {
        /// Referencing decision ID.
        decision_id: String,
        /// Missing target decision ID.
        target: String,
    },
    /// Sequence numbers were not contiguous `0, 1, 2, ...`.
    #[error("non-monotonic sequence at index {index}: expected {expected}, found {actual}")]
    NonMonotonicSeq {
        /// Slice index.
        index: usize,
        /// Expected sequence number.
        expected: u64,
        /// Observed sequence number.
        actual: u64,
    },
    /// Record's `prev_hash` did not equal the preceding record's `record_hash`.
    #[error("hash chain broken at seq {seq}: prev_hash mismatch")]
    PrevHashMismatch {
        /// Sequence number where chain broke.
        seq: u64,
    },
    /// Record's stored `record_hash` did not match recomputed canonical BLAKE3 digest.
    #[error("record tampered at seq {seq}: record_hash mismatch")]
    RecordHashMismatch {
        /// Sequence number with invalid digest.
        seq: u64,
    },
    /// Record's stored `mmr_root` did not match the recomputed MMR root over `0..=seq`.
    #[error("mmr root mismatch at seq {seq}")]
    MmrRootMismatch {
        /// Sequence number with invalid MMR root.
        seq: u64,
    },
    /// Observation `metadata_json` was not valid JSON for RFC 8785 JCS canonicalization.
    #[error("invalid metadata_json: {detail}")]
    InvalidMetadataJson {
        /// Parser diagnostic detail.
        detail: String,
    },
}

pub(crate) fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub(crate) fn validate_decision_draft(draft: &DecisionDraft) -> Result<(), ChainError> {
    if draft.decision_id.trim().is_empty() {
        return Err(ChainError::EmptyField {
            field: "decision_id",
        });
    }
    if draft.author.trim().is_empty() {
        return Err(ChainError::EmptyField { field: "author" });
    }
    if draft.rationale.trim().is_empty() {
        return Err(ChainError::EmptyField { field: "rationale" });
    }
    Ok(())
}

/// Computes the domain-separated canonical BLAKE3 digest for a [`DecisionRecord`].
#[must_use]
pub fn compute_decision_hash(seq: u64, prev_hash: BlobDigest, draft: &DecisionDraft) -> BlobDigest {
    let mut h = blake3::Hasher::new();
    h.update(b"hephaestus.decision.v1\0");
    h.update(&seq.to_le_bytes());
    h.update(prev_hash.as_bytes());
    update_len_prefixed(&mut h, draft.decision_id.as_bytes());
    update_len_prefixed(&mut h, draft.change_id.as_str().as_bytes());
    update_len_prefixed(&mut h, draft.op_id.as_str().as_bytes());
    update_len_prefixed(&mut h, draft.author.as_bytes());
    update_len_prefixed(&mut h, draft.status.as_str().as_bytes());
    update_len_prefixed(&mut h, draft.rationale.as_bytes());
    h.update(&(draft.alternatives.len() as u64).to_le_bytes());
    for alt in &draft.alternatives {
        update_len_prefixed(&mut h, alt.as_bytes());
    }
    match &draft.supersedes {
        Some(target) => {
            h.update(&[1u8]);
            update_len_prefixed(&mut h, target.as_bytes());
        }
        None => {
            h.update(&[0u8]);
        }
    }
    h.update(&draft.recorded_at_ms.to_le_bytes());
    BlobDigest(*h.finalize().as_bytes())
}

impl DecisionRecord {
    /// Extracts the underlying [`DecisionDraft`] fields for hash verification.
    #[must_use]
    pub fn as_draft(&self) -> DecisionDraft {
        DecisionDraft {
            decision_id: self.decision_id.clone(),
            change_id: self.change_id.clone(),
            op_id: self.op_id.clone(),
            author: self.author.clone(),
            status: self.status,
            rationale: self.rationale.clone(),
            alternatives: self.alternatives.clone(),
            supersedes: self.supersedes.clone(),
            recorded_at_ms: self.recorded_at_ms,
        }
    }

    /// Recomputes and returns the canonical BLAKE3 hash for this record.
    #[must_use]
    pub fn recompute_hash(&self) -> BlobDigest {
        compute_decision_hash(self.seq, self.prev_hash, &self.as_draft())
    }
}

/// Builds the Merkle Mountain Range over a sequence of [`DecisionRecord`] hashes.
#[must_use]
pub fn decision_chain_mmr(records: &[DecisionRecord]) -> Mmr {
    let mut mmr = Mmr::new();
    for rec in records {
        mmr.append(rec.record_hash);
    }
    mmr
}

/// Appends a validated, hash-chained [`DecisionRecord`] onto an in-memory decision chain.
pub fn append_decision_in_memory(
    chain: &mut Vec<DecisionRecord>,
    draft: DecisionDraft,
) -> Result<DecisionRecord, ChainError> {
    validate_decision_draft(&draft)?;
    if chain.iter().any(|r| r.decision_id == draft.decision_id) {
        return Err(ChainError::DuplicateId {
            id: draft.decision_id,
        });
    }
    if let Some(target) = &draft.supersedes
        && !chain.iter().any(|r| &r.decision_id == target)
    {
        return Err(ChainError::UnknownSupersedes {
            decision_id: draft.decision_id,
            target: target.clone(),
        });
    }
    let (seq, prev_hash) = match chain.last() {
        Some(last) => (last.seq.saturating_add(1), last.record_hash),
        None => (0, GENESIS_HASH),
    };
    let record_hash = compute_decision_hash(seq, prev_hash, &draft);
    let mut mmr = decision_chain_mmr(chain);
    mmr.append(record_hash);
    let mmr_root = mmr.root();
    let rec = DecisionRecord {
        seq,
        prev_hash,
        record_hash,
        mmr_root,
        decision_id: draft.decision_id,
        change_id: draft.change_id,
        op_id: draft.op_id,
        author: draft.author,
        status: draft.status,
        rationale: draft.rationale,
        alternatives: draft.alternatives,
        supersedes: draft.supersedes,
        recorded_at_ms: draft.recorded_at_ms,
    };
    chain.push(rec.clone());
    Ok(rec)
}

/// Verifies contiguous sequence numbers, `prev_hash` linkage, uniqueness, BLAKE3 digests, and MMR roots.
pub fn verify_decision_chain(records: &[DecisionRecord]) -> Result<(), ChainError> {
    let mut verifier = DecisionChainVerifier::new();
    for rec in records {
        verifier.step(rec)?;
    }
    Ok(())
}
