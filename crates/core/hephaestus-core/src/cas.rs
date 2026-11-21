//! BLAKE3 content-addressed storage digests, stream kinds, and idempotency keys.

use crate::bundler::INLINE_BLOB_THRESHOLD;
use crate::ids::RepoId;
use alloc::string::String;
use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error decoding a hexadecimal BLAKE3 digest.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HexDigestError {
    /// Input hex string did not have exactly 64 characters.
    #[error("expected 64 hex chars for BLAKE3 digest, got {0}")]
    InvalidLength(usize),
    /// Input contained a non-hexadecimal byte.
    #[error("invalid hexadecimal character at byte offset {0}")]
    InvalidHexByte(usize),
}

/// 32-byte BLAKE3 content digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct BlobDigest(pub [u8; 32]);

impl BlobDigest {
    /// Computes the BLAKE3 digest of `data`.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Returns the raw 32-byte digest array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Formats the digest as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Parses a 64-character lowercase or uppercase hexadecimal digest.
    pub fn from_hex(hex_str: &str) -> Result<Self, HexDigestError> {
        decode_hex(hex_str).map(Self)
    }
}

impl fmt::Debug for BlobDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobDigest({})", self.to_hex())
    }
}

impl fmt::Display for BlobDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Computes the BLAKE3 digest of `data`.
#[must_use]
pub fn hash_bytes(data: &[u8]) -> BlobDigest {
    BlobDigest::of(data)
}

/// Encodes arbitrary bytes as lowercase hexadecimal without allocations beyond output.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a 64-character hexadecimal string into a 32-byte digest.
pub fn decode_hex(s: &str) -> Result<[u8; 32], HexDigestError> {
    let raw = s.as_bytes();
    if raw.len() != 64 {
        return Err(HexDigestError::InvalidLength(raw.len()));
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in raw.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or(HexDigestError::InvalidHexByte(idx * 2))?;
        let lo = hex_nibble(chunk[1]).ok_or(HexDigestError::InvalidHexByte(idx * 2 + 1))?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Storage tier selected for a content-addressed blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobTier {
    /// Stored directly inside SQLite WAL (`<= 8 KiB`).
    Inline,
    /// Coalesced into a `GRNB0002` framed Zstd bundle (`> 8 KiB`).
    Packed,
}

impl BlobTier {
    /// Classifies a payload size using [`INLINE_BLOB_THRESHOLD`].
    #[must_use]
    pub const fn classify(byte_len: usize) -> Self {
        if byte_len <= INLINE_BLOB_THRESHOLD {
            Self::Inline
        } else {
            Self::Packed
        }
    }
}

/// Logical replication stream identifier used in idempotency keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    /// Content-addressed blob upload (`> 0` bytes).
    Blob,
    /// `GRNB0002` bundle flush.
    Bundle,
    /// Jujutsu operation / bookmark update.
    JjOp,
    /// Hash-chained Decision Log entry.
    Decision,
    /// Orthogonal Observation Log entry.
    Observation,
}

impl StreamKind {
    /// Returns the canonical wire and SQLite representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Bundle => "bundle",
            Self::JjOp => "jj_op",
            Self::Decision => "decision",
            Self::Observation => "observation",
        }
    }
}

/// Atomic idempotency key `(repo_id, stream_kind, blake3_digest)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey {
    /// Target repository identifier.
    pub repo_id: RepoId,
    /// Logical stream kind.
    pub stream_kind: StreamKind,
    /// BLAKE3 digest of the canonical payload.
    pub digest: BlobDigest,
}
