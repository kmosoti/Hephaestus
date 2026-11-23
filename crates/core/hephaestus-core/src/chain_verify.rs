//! Streaming `O(log N)`-memory hash-chain and MMR verifiers for Decision and Observation logs.

use crate::cas::BlobDigest;
use crate::decision_log::{
    ChainError, DecisionRecord, GENESIS_HASH, compute_decision_hash, validate_decision_draft,
};
use crate::mmr::{bag_mmr_peaks, compute_append_nodes};
use crate::observation_log::{
    ObservationRecord, compute_observation_hash, validate_observation_draft,
};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// Default page size applied when a Decision or Observation query omits `limit`.
pub const DEFAULT_LOG_PAGE_LIMIT: usize = 200;

/// Maximum page size permitted for Decision or Observation queries (`1000`).
pub const MAX_LOG_PAGE_LIMIT: usize = 1000;

#[derive(Debug, Clone, Default)]
struct StreamingMmr {
    leaf_count: u64,
    peaks: Vec<BlobDigest>,
}

impl StreamingMmr {
    fn append_and_root(
        &mut self,
        seq: u64,
        record_hash: BlobDigest,
    ) -> Result<BlobDigest, ChainError> {
        let out = compute_append_nodes(self.leaf_count, record_hash, &self.peaks)
            .map_err(|_| ChainError::MmrRootMismatch { seq })?;
        self.peaks = out.next_peaks;
        self.leaf_count = self.leaf_count.saturating_add(1);
        Ok(bag_mmr_peaks(self.leaf_count, &self.peaks))
    }
}

/// Incremental hash-chain + `O(log N)`-memory MMR verifier for Decision Log records.
#[derive(Debug, Clone)]
pub struct DecisionChainVerifier {
    expected_seq: u64,
    expected_prev: BlobDigest,
    seen_ids: BTreeSet<String>,
    mmr: StreamingMmr,
}

impl Default for DecisionChainVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DecisionChainVerifier {
    /// Creates a verifier starting at genesis (`seq = 0`, `GENESIS_HASH`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_seq: 0,
            expected_prev: GENESIS_HASH,
            seen_ids: BTreeSet::new(),
            mmr: StreamingMmr::default(),
        }
    }

    /// Validates the next sequential [`DecisionRecord`] in `0, 1, 2, ...` order.
    pub fn step(&mut self, rec: &DecisionRecord) -> Result<(), ChainError> {
        let idx = usize::try_from(self.expected_seq).unwrap_or(usize::MAX);
        if rec.seq != self.expected_seq {
            return Err(ChainError::NonMonotonicSeq {
                index: idx,
                expected: self.expected_seq,
                actual: rec.seq,
            });
        }
        if rec.prev_hash != self.expected_prev {
            return Err(ChainError::PrevHashMismatch { seq: rec.seq });
        }
        let draft = rec.as_draft();
        validate_decision_draft(&draft)?;
        if !self.seen_ids.insert(rec.decision_id.clone()) {
            return Err(ChainError::DuplicateId {
                id: rec.decision_id.clone(),
            });
        }
        if let Some(target) = &rec.supersedes
            && (target == &rec.decision_id || !self.seen_ids.contains(target))
        {
            return Err(ChainError::UnknownSupersedes {
                decision_id: rec.decision_id.clone(),
                target: target.clone(),
            });
        }
        if rec.record_hash != compute_decision_hash(rec.seq, rec.prev_hash, &draft) {
            return Err(ChainError::RecordHashMismatch { seq: rec.seq });
        }
        let mmr_root = self.mmr.append_and_root(rec.seq, rec.record_hash)?;
        if rec.mmr_root != mmr_root {
            return Err(ChainError::MmrRootMismatch { seq: rec.seq });
        }
        self.expected_prev = rec.record_hash;
        self.expected_seq = self.expected_seq.saturating_add(1);
        Ok(())
    }

    /// Returns total verified records processed so far.
    #[must_use]
    pub const fn verified_count(&self) -> u64 {
        self.expected_seq
    }
}

/// Incremental hash-chain + `O(log N)`-memory MMR verifier for Observation Log records.
#[derive(Debug, Clone)]
pub struct ObservationChainVerifier {
    expected_seq: u64,
    expected_prev: BlobDigest,
    seen_ids: BTreeSet<String>,
    mmr: StreamingMmr,
}

impl Default for ObservationChainVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationChainVerifier {
    /// Creates a verifier starting at genesis (`seq = 0`, `GENESIS_HASH`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_seq: 0,
            expected_prev: GENESIS_HASH,
            seen_ids: BTreeSet::new(),
            mmr: StreamingMmr::default(),
        }
    }

    /// Validates the next sequential [`ObservationRecord`] in `0, 1, 2, ...` order.
    pub fn step(&mut self, rec: &ObservationRecord) -> Result<(), ChainError> {
        self.step_with_options(rec, true)
    }

    /// Validates the next sequential [`ObservationRecord`], optionally skipping in-memory
    /// duplicate-ID tracking when backed by an already-verified SQLite `UNIQUE` constraint.
    pub fn step_with_options(
        &mut self,
        rec: &ObservationRecord,
        track_seen_ids: bool,
    ) -> Result<(), ChainError> {
        let idx = usize::try_from(self.expected_seq).unwrap_or(usize::MAX);
        if rec.seq != self.expected_seq {
            return Err(ChainError::NonMonotonicSeq {
                index: idx,
                expected: self.expected_seq,
                actual: rec.seq,
            });
        }
        if rec.prev_hash != self.expected_prev {
            return Err(ChainError::PrevHashMismatch { seq: rec.seq });
        }
        let draft = rec.as_draft();
        validate_observation_draft(&draft)?;
        if track_seen_ids && !self.seen_ids.insert(rec.observation_id.clone()) {
            return Err(ChainError::DuplicateId {
                id: rec.observation_id.clone(),
            });
        }
        if rec.record_hash != compute_observation_hash(rec.seq, rec.prev_hash, &draft) {
            return Err(ChainError::RecordHashMismatch { seq: rec.seq });
        }
        let mmr_root = self.mmr.append_and_root(rec.seq, rec.record_hash)?;
        if rec.mmr_root != mmr_root {
            return Err(ChainError::MmrRootMismatch { seq: rec.seq });
        }
        self.expected_prev = rec.record_hash;
        self.expected_seq = self.expected_seq.saturating_add(1);
        Ok(())
    }

    /// Returns total verified records processed so far.
    #[must_use]
    pub const fn verified_count(&self) -> u64 {
        self.expected_seq
    }
}
