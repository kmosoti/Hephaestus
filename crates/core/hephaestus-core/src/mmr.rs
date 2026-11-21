//! Pure `#![no_std]` BLAKE3 Merkle Mountain Range (MMR) with `O(log N)` inclusion proofs.

use crate::cas::BlobDigest;
use crate::decision_log::GENESIS_HASH;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors emitted while constructing or verifying MMR inclusion proofs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MmrError {
    /// Requested `leaf_index` was outside `0..leaf_count`.
    #[error("mmr leaf index {leaf_index} out of bounds for {leaf_count} leaves")]
    LeafOutOfBounds {
        /// Requested zero-based leaf index.
        leaf_index: u64,
        /// Active leaf count in the MMR.
        leaf_count: u64,
    },
    /// Required node was absent from storage during proof construction.
    #[error("missing mmr node at position {pos}")]
    MissingNode {
        /// Zero-based post-order node position.
        pos: u64,
    },
    /// Proof structure or peak count did not match `leaf_count`.
    #[error("malformed mmr inclusion proof")]
    InvalidProof,
}

/// One sibling hash along the Merkle path from a leaf to its mountain peak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrSibling {
    /// 32-byte BLAKE3 digest of the sibling node.
    pub hash: BlobDigest,
    /// `true` when this sibling is the right child of the parent node.
    pub is_right: bool,
}

/// Compact `O(log N)` MMR inclusion proof for one leaf against an MMR root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProof {
    /// Zero-based leaf index being proved.
    pub leaf_index: u64,
    /// Total leaves committed in the target MMR root.
    pub leaf_count: u64,
    /// Sibling path from leaf to its mountain peak (`<= log2(leaf_count)`).
    pub siblings: Vec<MmrSibling>,
    /// Ordered mountain peaks (`<= log2(leaf_count)`), highest mountain first.
    pub peaks: Vec<BlobDigest>,
    /// Index into [`Self::peaks`] corresponding to the leaf's mountain.
    pub peak_index: usize,
}

/// Hashes a leaf payload digest with domain separation and leaf index.
#[must_use]
pub fn hash_mmr_leaf(leaf_index: u64, payload_digest: BlobDigest) -> BlobDigest {
    let mut h = blake3::Hasher::new();
    h.update(b"hephaestus.mmr.leaf.v1\0");
    h.update(&leaf_index.to_le_bytes());
    h.update(payload_digest.as_bytes());
    BlobDigest(*h.finalize().as_bytes())
}

/// Hashes an internal MMR parent node from its position and left/right children.
#[must_use]
pub fn hash_mmr_node(pos: u64, left: BlobDigest, right: BlobDigest) -> BlobDigest {
    let mut h = blake3::Hasher::new();
    h.update(b"hephaestus.mmr.node.v1\0");
    h.update(&pos.to_le_bytes());
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    BlobDigest(*h.finalize().as_bytes())
}

/// Bags mountain peaks together with `leaf_count` into a single 32-byte MMR root digest.
#[must_use]
pub fn bag_mmr_peaks(leaf_count: u64, peaks: &[BlobDigest]) -> BlobDigest {
    if leaf_count == 0 || peaks.is_empty() {
        return GENESIS_HASH;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"hephaestus.mmr.root.v1\0");
    h.update(&leaf_count.to_le_bytes());
    for peak in peaks {
        h.update(peak.as_bytes());
    }
    BlobDigest(*h.finalize().as_bytes())
}

/// Maps a zero-based leaf index to its zero-based post-order MMR node position.
#[must_use]
pub const fn leaf_index_to_pos(leaf_index: u64) -> u64 {
    2 * leaf_index - (leaf_index.count_ones() as u64)
}

/// Returns total MMR node count for `leaf_count` appended leaves.
#[must_use]
pub const fn leaf_count_to_mmr_size(leaf_count: u64) -> u64 {
    2 * leaf_count - (leaf_count.count_ones() as u64)
}

/// Returns the ordered zero-based post-order peak positions for `leaf_count` leaves.
#[must_use]
pub fn peak_positions(leaf_count: u64) -> Vec<u64> {
    let mut peaks = Vec::new();
    let mut offset = 0u64;
    for bit in (0..64u32).rev() {
        if (leaf_count & (1u64 << bit)) != 0 {
            let mountain_nodes = (1u64 << (bit + 1)) - 1;
            peaks.push(offset + mountain_nodes - 1);
            offset += mountain_nodes;
        }
    }
    peaks
}

/// Node positions needed to assemble an `O(log N)` inclusion proof from persistent storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrProofPlan {
    /// Sibling `(node_pos, is_right)` entries walking up to the leaf's mountain peak.
    pub sibling_positions: Vec<(u64, bool)>,
    /// Index into [`Self::peak_positions`] corresponding to the leaf's mountain.
    pub peak_index: usize,
    /// Ordered post-order node positions of all active mountain peaks.
    pub peak_positions: Vec<u64>,
}

/// Result of appending one leaf to an MMR from its existing peaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrAppendOutput {
    /// Newly created `(node_pos, node_hash)` entries to persist.
    pub created_nodes: Vec<(u64, BlobDigest)>,
    /// Updated ordered mountain peak hashes after the append.
    pub next_peaks: Vec<BlobDigest>,
}

/// Computes the exact node positions needed for an `O(log N)` inclusion proof.
pub fn proof_node_positions(leaf_index: u64, leaf_count: u64) -> Result<MmrProofPlan, MmrError> {
    if leaf_index >= leaf_count {
        return Err(MmrError::LeafOutOfBounds {
            leaf_index,
            leaf_count,
        });
    }
    let mut peak_pos = Vec::new();
    let mut offset = 0u64;
    let mut leaf_cursor = 0u64;
    let mut target_peak_idx = 0usize;
    let mut target_height = 0u32;
    let mut target_local_leaf = 0u64;

    for bit in (0..64u32).rev() {
        if (leaf_count & (1u64 << bit)) != 0 {
            let m_leaves = 1u64 << bit;
            let m_nodes = (1u64 << (bit + 1)) - 1;
            let p_idx = peak_pos.len();
            peak_pos.push(offset + m_nodes - 1);
            if leaf_index >= leaf_cursor && leaf_index < leaf_cursor + m_leaves {
                target_peak_idx = p_idx;
                target_height = bit;
                target_local_leaf = leaf_index - leaf_cursor;
            }
            offset += m_nodes;
            leaf_cursor += m_leaves;
        }
    }

    let mut cur_pos = leaf_index_to_pos(leaf_index);
    let mut siblings = Vec::with_capacity(target_height as usize);
    for step in 0..target_height {
        let sub_nodes = (1u64 << (step + 1)) - 1;
        let is_right_child = ((target_local_leaf >> step) & 1) == 1;
        if is_right_child {
            siblings.push((cur_pos - sub_nodes, false));
            cur_pos += 1;
        } else {
            let right_sib = cur_pos + sub_nodes;
            siblings.push((right_sib, true));
            cur_pos = right_sib + 1;
        }
    }
    Ok(MmrProofPlan {
        sibling_positions: siblings,
        peak_index: target_peak_idx,
        peak_positions: peak_pos,
    })
}

/// Computes newly created `(node_pos, node_hash)` entries when appending `leaf_index`
/// given the existing peaks for `leaf_index` prior leaves.
pub fn compute_append_nodes(
    leaf_index: u64,
    payload_digest: BlobDigest,
    prior_peaks: &[BlobDigest],
) -> Result<MmrAppendOutput, MmrError> {
    if prior_peaks.len() != leaf_index.count_ones() as usize {
        return Err(MmrError::InvalidProof);
    }
    let mut created = Vec::new();
    let mut peaks = prior_peaks.to_vec();
    let mut cur_pos = leaf_index_to_pos(leaf_index);
    let mut cur_hash = hash_mmr_leaf(leaf_index, payload_digest);
    created.push((cur_pos, cur_hash));

    for _ in 0..leaf_index.trailing_ones() {
        let left_peak = peaks.pop().ok_or(MmrError::InvalidProof)?;
        cur_pos += 1;
        cur_hash = hash_mmr_node(cur_pos, left_peak, cur_hash);
        created.push((cur_pos, cur_hash));
    }
    peaks.push(cur_hash);
    Ok(MmrAppendOutput {
        created_nodes: created,
        next_peaks: peaks,
    })
}

/// Verifies an [`MmrProof`] for `payload_digest` against `expected_root` in `O(log N)` time.
#[must_use]
pub fn verify_inclusion_proof(
    proof: &MmrProof,
    payload_digest: BlobDigest,
    expected_root: BlobDigest,
) -> bool {
    let Ok(plan) = proof_node_positions(proof.leaf_index, proof.leaf_count) else {
        return false;
    };
    if proof.siblings.len() != plan.sibling_positions.len()
        || proof.peak_index != plan.peak_index
        || proof.peaks.len() != proof.leaf_count.count_ones() as usize
    {
        return false;
    }

    let mut cur_pos = leaf_index_to_pos(proof.leaf_index);
    let mut cur_hash = hash_mmr_leaf(proof.leaf_index, payload_digest);
    for (step, (sib, &(expected_sib_pos, expected_is_right))) in proof
        .siblings
        .iter()
        .zip(plan.sibling_positions.iter())
        .enumerate()
    {
        if sib.is_right != expected_is_right {
            return false;
        }
        let sub_nodes = (1u64 << (step + 1)) - 1;
        if sib.is_right {
            if cur_pos + sub_nodes != expected_sib_pos {
                return false;
            }
            cur_pos = expected_sib_pos + 1;
            cur_hash = hash_mmr_node(cur_pos, cur_hash, sib.hash);
        } else {
            if cur_pos.checked_sub(sub_nodes) != Some(expected_sib_pos) {
                return false;
            }
            cur_pos += 1;
            cur_hash = hash_mmr_node(cur_pos, sib.hash, cur_hash);
        }
    }

    if proof.peaks.get(proof.peak_index) != Some(&cur_hash) {
        return false;
    }
    bag_mmr_peaks(proof.leaf_count, &proof.peaks) == expected_root
}

/// In-memory BLAKE3 Merkle Mountain Range supporting append, root/peaks, and inclusion proofs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mmr {
    nodes: Vec<BlobDigest>,
    leaf_count: u64,
}

impl Mmr {
    /// Creates an empty MMR.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            leaf_count: 0,
        }
    }

    /// Number of leaves appended to this MMR.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Total number of nodes (leaves + merged parents) stored.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Appends `payload_digest` and returns the newly created `(pos, digest)` pairs.
    pub fn append(&mut self, payload_digest: BlobDigest) -> Vec<(u64, BlobDigest)> {
        let Ok(out) = compute_append_nodes(self.leaf_count, payload_digest, &self.peaks()) else {
            return Vec::new();
        };
        self.nodes.extend(out.created_nodes.iter().map(|&(_, h)| h));
        self.leaf_count += 1;
        out.created_nodes
    }

    /// Returns the ordered mountain peak digests from highest to lowest mountain.
    #[must_use]
    pub fn peaks(&self) -> Vec<BlobDigest> {
        peak_positions(self.leaf_count)
            .into_iter()
            .filter_map(|p| self.nodes.get(p as usize).copied())
            .collect()
    }

    /// Returns the current 32-byte MMR root digest (or [`GENESIS_HASH`] when empty).
    #[must_use]
    pub fn root(&self) -> BlobDigest {
        bag_mmr_peaks(self.leaf_count, &self.peaks())
    }

    /// Generates an `O(log N)` inclusion proof for `leaf_index`.
    pub fn inclusion_proof(&self, leaf_index: u64) -> Result<MmrProof, MmrError> {
        let plan = proof_node_positions(leaf_index, self.leaf_count)?;
        let mut siblings = Vec::with_capacity(plan.sibling_positions.len());
        for (pos, is_right) in plan.sibling_positions {
            let hash = *self
                .nodes
                .get(pos as usize)
                .ok_or(MmrError::MissingNode { pos })?;
            siblings.push(MmrSibling { hash, is_right });
        }
        let mut peaks = Vec::with_capacity(plan.peak_positions.len());
        for pos in plan.peak_positions {
            let hash = *self
                .nodes
                .get(pos as usize)
                .ok_or(MmrError::MissingNode { pos })?;
            peaks.push(hash);
        }
        Ok(MmrProof {
            leaf_index,
            leaf_count: self.leaf_count,
            siblings,
            peaks,
            peak_index: plan.peak_index,
        })
    }
}
