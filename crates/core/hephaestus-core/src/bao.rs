//! Pure `#![no_std]` BLAKE3 binary Merkle tree verified-streaming (`Bao`) encoder/decoder.
//!
//! Uses 1 KiB leaf chunks with BLAKE3 domain-separated leaf and parent chaining values so callers
//! can verify arbitrary byte ranges against a 32-byte root hash without fetching the full blob.

use crate::cas::BlobDigest;
use alloc::vec::Vec;
use thiserror::Error;

pub use crate::bao_slice::{decode_inboard, extract_slice_from_outboard, verify_and_decode_slice};

/// Leaf chunk size (1 KiB) for verified streaming proofs.
pub const BAO_CHUNK_LEN: usize = 1024;
/// Encoded size of one parent node (`left_cv: 32B || right_cv: 32B`).
pub const BAO_PARENT_LEN: usize = 64;
/// Byte length of the leading `total_len` header in outboard/inboard/slice encodings.
pub const BAO_HEADER_LEN: usize = 8;

/// Errors produced when encoding, slicing, or verifying Bao Merkle trees.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BaoError {
    /// Encoding header, tree layout, or length prefix was malformed.
    #[error("malformed bao encoding")]
    InvalidEncoding,
    /// Input ended before all required parent nodes or leaf bytes were read.
    #[error("truncated bao stream or proof")]
    Truncated,
    /// Requested byte range fell outside `[0..total_len]`.
    #[error("bao slice [{start}..+{len}] out of bounds for {total_len}-byte blob")]
    SliceOutOfBounds {
        /// Requested byte start offset.
        start: u64,
        /// Requested byte length.
        len: u64,
        /// Total blob length committed in the tree header.
        total_len: u64,
    },
    /// Recomputed chaining value did not match expected parent or root digest.
    #[error("bao cryptographic hash mismatch")]
    HashMismatch,
}

/// Separate Merkle outboard paired with the 32-byte root digest and original length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaoOutboard {
    /// 32-byte BLAKE3 Merkle tree root hash.
    pub root: BlobDigest,
    /// Original unencoded payload length in bytes.
    pub total_len: u64,
    /// Pre-order encoded header (`u64 total_len`) + 64-byte parent chaining value pairs.
    pub outboard: Vec<u8>,
}

pub(crate) fn leaf_hash(chunk_idx: u64, chunk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"hephaestus.bao.leaf.v1\0");
    h.update(&chunk_idx.to_le_bytes());
    h.update(&(chunk.len() as u32).to_le_bytes());
    h.update(chunk);
    *h.finalize().as_bytes()
}

pub(crate) fn parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"hephaestus.bao.parent.v1\0");
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

pub(crate) const fn chunk_count(total_len: u64) -> u64 {
    if total_len == 0 {
        1
    } else {
        total_len.div_ceil(BAO_CHUNK_LEN as u64)
    }
}

pub(crate) const fn left_subtree_chunks(chunks: u64) -> u64 {
    1u64 << (u64::BITS - 1 - (chunks - 1).leading_zeros())
}

pub(crate) fn chunk_byte_len(total_len: u64, chunk_idx: u64) -> usize {
    let start = chunk_idx.saturating_mul(BAO_CHUNK_LEN as u64);
    total_len.saturating_sub(start).min(BAO_CHUNK_LEN as u64) as usize
}

pub(crate) fn read_u64_le(buf: &[u8], cursor: &mut usize) -> Result<u64, BaoError> {
    let end = cursor.checked_add(8).ok_or(BaoError::Truncated)?;
    let slice = buf.get(*cursor..end).ok_or(BaoError::Truncated)?;
    *cursor = end;
    let arr: [u8; 8] = slice.try_into().map_err(|_| BaoError::InvalidEncoding)?;
    Ok(u64::from_le_bytes(arr))
}

pub(crate) fn read_parent(
    buf: &[u8],
    cursor: &mut usize,
) -> Result<([u8; 32], [u8; 32]), BaoError> {
    let end = cursor
        .checked_add(BAO_PARENT_LEN)
        .ok_or(BaoError::Truncated)?;
    let slice = buf.get(*cursor..end).ok_or(BaoError::Truncated)?;
    *cursor = end;
    let left: [u8; 32] = slice[0..32]
        .try_into()
        .map_err(|_| BaoError::InvalidEncoding)?;
    let right: [u8; 32] = slice[32..64]
        .try_into()
        .map_err(|_| BaoError::InvalidEncoding)?;
    Ok((left, right))
}

fn build_tree(
    data: &[u8],
    first_chunk: u64,
    chunks: u64,
    include_leaves: bool,
    out: &mut Vec<u8>,
) -> [u8; 32] {
    if chunks == 1 {
        let start = (first_chunk as usize).saturating_mul(BAO_CHUNK_LEN);
        let end = start.saturating_add(BAO_CHUNK_LEN).min(data.len());
        let slice = if start <= data.len() {
            &data[start..end]
        } else {
            &[]
        };
        if include_leaves {
            out.extend_from_slice(slice);
        }
        return leaf_hash(first_chunk, slice);
    }
    let left_c = left_subtree_chunks(chunks);
    let pos = out.len();
    out.resize(pos + BAO_PARENT_LEN, 0);
    let l_cv = build_tree(data, first_chunk, left_c, include_leaves, out);
    let r_cv = build_tree(
        data,
        first_chunk + left_c,
        chunks - left_c,
        include_leaves,
        out,
    );
    out[pos..pos + 32].copy_from_slice(&l_cv);
    out[pos + 32..pos + 64].copy_from_slice(&r_cv);
    parent_hash(&l_cv, &r_cv)
}

/// Computes the 32-byte Bao Merkle root hash for `data`.
#[must_use]
pub fn bao_root_hash(data: &[u8]) -> BlobDigest {
    encode_outboard(data).root
}

/// Encodes `data` into a separate [`BaoOutboard`] (header + pre-order parent nodes).
#[must_use]
pub fn encode_outboard(data: &[u8]) -> BaoOutboard {
    let total_len = data.len() as u64;
    let chunks = chunk_count(total_len);
    let mut outboard =
        Vec::with_capacity(BAO_HEADER_LEN + (chunks.saturating_sub(1) as usize) * BAO_PARENT_LEN);
    outboard.extend_from_slice(&total_len.to_le_bytes());
    let root = build_tree(data, 0, chunks, false, &mut outboard);
    BaoOutboard {
        root: BlobDigest(root),
        total_len,
        outboard,
    }
}

/// Encodes `data` into an interleaved inboard stream (`total_len` + parent nodes + leaf chunks).
#[must_use]
pub fn encode_inboard(data: &[u8]) -> (BlobDigest, Vec<u8>) {
    let total_len = data.len() as u64;
    let chunks = chunk_count(total_len);
    let mut encoded = Vec::with_capacity(
        BAO_HEADER_LEN + (chunks.saturating_sub(1) as usize) * BAO_PARENT_LEN + data.len(),
    );
    encoded.extend_from_slice(&total_len.to_le_bytes());
    let root = build_tree(data, 0, chunks, true, &mut encoded);
    (BlobDigest(root), encoded)
}
