//! Pure Sans-I/O content-addressed `GRNB0002` framed Zstd bundle packer.

use crate::bundler_frames::{FrameDesc, encode_frame, write_frame_desc};
use crate::cas::encode_hex;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use thiserror::Error;

pub use crate::bundler_frames::{
    BundleDirectoryHeader, FrameDesc as BundleFrameDesc, bundle_frame_count,
    parse_frame_directory_header, unpack_blob_from_bundle, unpack_blob_from_frame,
};

/// Blobs at or below 8 KiB stay inline in SQLite WAL; larger blobs pack into Zstd bundles.
pub const INLINE_BLOB_THRESHOLD: usize = 8 * 1024;
/// Minimum target bundle raw size before automatic flush (4 MiB).
pub const TARGET_BUNDLE_MIN_BYTES: usize = 4 * 1024 * 1024;
/// Maximum target bundle raw size (32 MiB).
pub const TARGET_BUNDLE_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Upper target for raw bytes per independent Zstd frame in `GRNB0002` bundles.
pub const MAX_FRAME_RAW_BYTES: usize = 256 * 1024;

/// Legacy single-stream Zstd bundle magic (`GRNB0001`).
pub const BUNDLE_MAGIC_V1: &[u8; 8] = b"GRNB0001";
/// Framed random-access Zstd bundle magic (`GRNB0002`).
pub const BUNDLE_MAGIC_V2: &[u8; 8] = b"GRNB0002";

pub(crate) const DIR_HEADER_LEN: usize = 12;
pub(crate) const FRAME_DESC_LEN: usize = 24;
const MANIFEST_ENTRY_LEN: usize = 44;

/// Errors produced when packing or unpacking `GRNB0001` / `GRNB0002` bundles.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleError {
    /// Zstd compression or decompression failed.
    #[error("bundle Zstd compression/decompression failed: {0}")]
    Zstd(String),

    /// Header, directory, or frame framing failed validation.
    #[error("corrupt bundle header or magic mismatch")]
    InvalidFormat,

    /// Prefix buffer contained a valid `GRNB0002` header but stopped before the full directory ended.
    #[error("bundle directory truncated: need {required_bytes} bytes")]
    TruncatedDirectory {
        /// Exact byte length required from offset `0` to parse all frame descriptors.
        required_bytes: usize,
    },

    /// Requested byte slice lies outside the containing frame or bundle.
    #[error("requested slice [{offset}..+{len}] out of bounds for bundle ({total} bytes)")]
    SliceOutOfBounds {
        /// Requested byte offset.
        offset: usize,
        /// Requested byte length.
        len: usize,
        /// Total raw payload length declared in bundle.
        total: usize,
    },

    /// Unpacked slice did not match expected BLAKE3 digest.
    #[error("BLAKE3 checksum mismatch for unpacked blob")]
    ChecksumMismatch,
}

/// Entry descriptor mapping a BLAKE3 hash to its offset inside a sealed bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    /// 32-byte BLAKE3 digest of the raw blob.
    pub blake3_hash: [u8; 32],
    /// Raw byte offset inside the bundle's logical payload space.
    pub byte_offset: u64,
    /// Raw byte length of the blob.
    pub byte_len: u32,
}

/// Sealed `GRNB0002` framed Zstd bundle ready for object-backend upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBundle {
    /// Deterministic bundle identifier derived from compressed bundle BLAKE3 digest.
    pub bundle_id: String,
    /// Compressed `GRNB0002` bundle bytes.
    pub compressed_bytes: Vec<u8>,
    /// Total logical uncompressed payload length including manifest header.
    pub raw_bytes_len: usize,
    /// Ordered manifest entries for every blob packed in this bundle.
    pub entries: Vec<BundleEntry>,
}

pub(crate) fn zstd_err(err: impl fmt::Display) -> BundleError {
    BundleError::Zstd(err.to_string())
}

/// Pure Sans-I/O content-addressed bundle packer coalescing blobs into framed Zstd archives.
#[derive(Debug, Clone)]
pub struct BundleAccumulator {
    target_bytes: usize,
    pending_hashes: Vec<[u8; 32]>,
    pending_hash_set: BTreeSet<[u8; 32]>,
    pending_payloads: Vec<Vec<u8>>,
    pending_raw_bytes: usize,
}

impl BundleAccumulator {
    /// Creates a new bundle accumulator targeting `target_bytes` (minimum 1024).
    #[must_use]
    pub fn new(target_bytes: usize) -> Self {
        Self {
            target_bytes: target_bytes.max(1024),
            pending_hashes: Vec::new(),
            pending_hash_set: BTreeSet::new(),
            pending_payloads: Vec::new(),
            pending_raw_bytes: 0,
        }
    }

    /// Returns `true` when `data` is small enough for inline SQLite storage.
    #[must_use]
    pub const fn should_inline(data: &[u8]) -> bool {
        data.len() <= INLINE_BLOB_THRESHOLD
    }

    /// Returns `true` when `hash` is already staged in this accumulator (`O(log N)`).
    #[must_use]
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.pending_hash_set.contains(hash)
    }

    /// Returns a cloned copy of a staged blob if present.
    #[must_use]
    pub fn peek_blob(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        if !self.pending_hash_set.contains(hash) {
            return None;
        }
        let pos = self.pending_hashes.iter().position(|h| h == hash)?;
        Some(self.pending_payloads[pos].clone())
    }

    /// Hashes `data` with BLAKE3 and stages it unless already present.
    pub fn push(&mut self, data: Vec<u8>) -> [u8; 32] {
        let hash = *blake3::hash(&data).as_bytes();
        self.push_prehashed(hash, data);
        hash
    }

    /// Stages `data` under caller-verified `hash` unless already present.
    pub fn push_prehashed(&mut self, hash: [u8; 32], data: Vec<u8>) {
        if !self.pending_hash_set.insert(hash) {
            return;
        }
        self.pending_raw_bytes = self.pending_raw_bytes.saturating_add(data.len());
        self.pending_hashes.push(hash);
        self.pending_payloads.push(data);
    }

    /// Number of staged blobs awaiting sealing.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_hashes.len()
    }

    /// Total raw uncompressed bytes staged.
    #[must_use]
    pub const fn pending_bytes(&self) -> usize {
        self.pending_raw_bytes
    }

    /// Returns `true` when staged raw bytes reached the target bundle threshold.
    #[must_use]
    pub const fn ready_to_seal(&self) -> bool {
        self.pending_raw_bytes >= self.target_bytes
    }

    /// Seals staged blobs into one deterministic `GRNB0002` framed Zstd bundle.
    pub fn seal(&mut self) -> Result<Option<SealedBundle>, BundleError> {
        if self.pending_hashes.is_empty() {
            return Ok(None);
        }
        let count = self.pending_hashes.len();
        let count_u32 = u32::try_from(count).map_err(|_| BundleError::InvalidFormat)?;
        let header_raw_len = count
            .checked_mul(MANIFEST_ENTRY_LEN)
            .and_then(|n| n.checked_add(DIR_HEADER_LEN))
            .ok_or(BundleError::InvalidFormat)?;
        let header_raw_u32 =
            u32::try_from(header_raw_len).map_err(|_| BundleError::InvalidFormat)?;

        let mut entries = Vec::with_capacity(count);
        let mut frame_plan: Vec<(usize, u32)> = Vec::new();
        let mut cursor = header_raw_len as u64;
        let (mut cur_blobs, mut cur_bytes) = (0usize, 0usize);

        for (hash, payload) in self.pending_hashes.iter().zip(&self.pending_payloads) {
            let len = u32::try_from(payload.len()).map_err(|_| BundleError::InvalidFormat)?;
            entries.push(BundleEntry {
                blake3_hash: *hash,
                byte_offset: cursor,
                byte_len: len,
            });
            if cur_blobs > 0 && cur_bytes.saturating_add(payload.len()) > MAX_FRAME_RAW_BYTES {
                let frame_u32 = u32::try_from(cur_bytes).map_err(|_| BundleError::InvalidFormat)?;
                frame_plan.push((cur_blobs, frame_u32));
                cur_blobs = 0;
                cur_bytes = 0;
            }
            cur_blobs += 1;
            cur_bytes = cur_bytes
                .checked_add(payload.len())
                .ok_or(BundleError::InvalidFormat)?;
            cursor = cursor
                .checked_add(u64::from(len))
                .ok_or(BundleError::InvalidFormat)?;
        }
        if cur_blobs > 0 {
            let frame_u32 = u32::try_from(cur_bytes).map_err(|_| BundleError::InvalidFormat)?;
            frame_plan.push((cur_blobs, frame_u32));
        }

        let total_frames = 1 + frame_plan.len();
        let total_frames_u32 =
            u32::try_from(total_frames).map_err(|_| BundleError::InvalidFormat)?;
        let dir_len = DIR_HEADER_LEN + total_frames * FRAME_DESC_LEN;

        let mut compressed = Vec::with_capacity(dir_len + (self.pending_raw_bytes / 2).max(4096));
        compressed.resize(dir_len, 0);
        compressed[0..8].copy_from_slice(BUNDLE_MAGIC_V2);
        compressed[8..12].copy_from_slice(&total_frames_u32.to_le_bytes());

        let mut frame_raw = Vec::with_capacity(header_raw_len.max(MAX_FRAME_RAW_BYTES));
        frame_raw.extend_from_slice(BUNDLE_MAGIC_V2);
        frame_raw.extend_from_slice(&count_u32.to_le_bytes());
        let mut rec = [0u8; MANIFEST_ENTRY_LEN];
        for entry in &entries {
            rec[0..32].copy_from_slice(&entry.blake3_hash);
            rec[32..40].copy_from_slice(&entry.byte_offset.to_le_bytes());
            rec[40..44].copy_from_slice(&entry.byte_len.to_le_bytes());
            frame_raw.extend_from_slice(&rec);
        }
        let (h_off, h_len) = encode_frame(&mut compressed, &frame_raw)?;
        write_frame_desc(
            &mut compressed,
            0,
            FrameDesc {
                raw_offset: 0,
                raw_len: header_raw_u32,
                comp_offset: h_off,
                comp_len: h_len,
            },
        );

        let mut payloads = core::mem::take(&mut self.pending_payloads).into_iter();
        self.pending_hashes.clear();
        self.pending_hash_set.clear();
        self.pending_raw_bytes = 0;

        let mut raw_cursor = header_raw_len as u64;
        for (idx, (blob_count, frame_raw_len)) in frame_plan.into_iter().enumerate() {
            frame_raw.clear();
            for _ in 0..blob_count {
                if let Some(payload) = payloads.next() {
                    frame_raw.extend_from_slice(&payload);
                }
            }
            let (comp_offset, comp_len) = encode_frame(&mut compressed, &frame_raw)?;
            write_frame_desc(
                &mut compressed,
                idx + 1,
                FrameDesc {
                    raw_offset: raw_cursor,
                    raw_len: frame_raw_len,
                    comp_offset,
                    comp_len,
                },
            );
            raw_cursor += u64::from(frame_raw_len);
        }

        let raw_bytes_len = usize::try_from(cursor).map_err(|_| BundleError::InvalidFormat)?;
        let bundle_hash = blake3::hash(&compressed);
        let hex_full = encode_hex(bundle_hash.as_bytes());
        let bundle_id = format!("bundle-{}.grnb.zst", &hex_full[..16]);

        Ok(Some(SealedBundle {
            bundle_id,
            compressed_bytes: compressed,
            raw_bytes_len,
            entries,
        }))
    }
}
