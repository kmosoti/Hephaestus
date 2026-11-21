//! Pure `#![no_std]` Litestream `"LTX1"` binary wire format with CRC-64/ISO verification.

pub use crate::crc64::{crc64_iso, crc64_iso_update};
use alloc::vec;
use alloc::vec::Vec;
use thiserror::Error;

/// 4-byte magic prefix identifying Litestream LTX v1 wire format.
pub const LTX_MAGIC: &[u8; 4] = b"LTX1";
/// Fixed LTX v1 binary header size in bytes.
pub const LTX_HEADER_SIZE: usize = 100;
/// Fixed LTX v1 binary trailer size in bytes (`post_apply_checksum` + `file_checksum`).
pub const LTX_TRAILER_SIZE: usize = 16;
/// MSB bit flag set on non-zero LTX rolling database and file checksums.
pub const LTX_CHECKSUM_FLAG: u64 = 1u64 << 63;

/// Computes the LTX per-page CRC-64/ISO checksum over `(pgno_be || page_bytes)` with MSB flag set.
#[must_use]
pub fn ltx_page_checksum(pgno: u32, page: &[u8]) -> u64 {
    let crc = crc64_iso_update(crc64_iso_update(0, &pgno.to_be_bytes()), page);
    crc | LTX_CHECKSUM_FLAG
}

/// Computes the rolling LTX database checksum by XOR-folding all page checksums and setting MSB.
#[must_use]
pub fn compute_db_checksum<'a>(pages: impl IntoIterator<Item = (u32, &'a [u8])>) -> u64 {
    let (mut acc, mut any) = (0u64, false);
    for (pgno, page) in pages {
        acc ^= ltx_page_checksum(pgno, page);
        any = true;
    }
    if any { acc | LTX_CHECKSUM_FLAG } else { 0 }
}

/// Errors produced when encoding, decoding, or reconstructing `"LTX1"` files.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LtxError {
    /// Input was shorter than the 100B header + 4B terminator + 16B trailer.
    #[error("truncated LTX1 payload")]
    Truncated,
    /// Magic bytes were not `"LTX1"`.
    #[error("invalid LTX1 magic header")]
    InvalidMagic,
    /// Invalid SQLite page size (must be power of two in `[512..=65536]`).
    #[error("invalid LTX1 page size: {0}")]
    InvalidPageSize(u32),
    /// Transaction ID range was invalid (`min_txid == 0` or `min_txid > max_txid`).
    #[error("invalid LTX1 txid range [{min}..={max}]")]
    InvalidTxidRange {
        /// Minimum txid.
        min: u64,
        /// Maximum txid.
        max: u64,
    },
    /// Page frames were not strictly ascending by 1-based `pgno`, or exceeded `commit`.
    #[error("invalid or out-of-order LTX1 page number {pgno}")]
    InvalidPageOrder {
        /// Offending 1-based page number.
        pgno: u32,
    },
    /// Page frame length did not equal `header.page_size`.
    #[error("page frame length {actual} did not match page_size {expected}")]
    PageSizeMismatch {
        /// Expected page size from header.
        expected: u32,
        /// Actual page buffer length.
        actual: usize,
    },
    /// Trailer CRC-64/ISO file checksum did not match recomputed bytes.
    #[error("LTX1 file CRC-64 checksum mismatch")]
    FileChecksumMismatch,
    /// Full snapshot reconstructed database checksum did not match trailer `post_apply_checksum`.
    #[error("LTX1 post-apply database checksum mismatch")]
    PostApplyChecksumMismatch,
}

/// 100-byte Litestream `"LTX1"` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtxHeader {
    /// Format flags (currently `0`).
    pub flags: u32,
    /// SQLite page size in bytes (e.g. `16384`).
    pub page_size: u32,
    /// Total database page count after applying this LTX file.
    pub commit: u32,
    /// Inclusive starting transaction ID (`1` for full snapshots).
    pub min_txid: u64,
    /// Inclusive ending transaction ID (`>= min_txid`).
    pub max_txid: u64,
    /// Creation timestamp in Unix milliseconds.
    pub timestamp_ms: i64,
    /// Rolling database checksum before applying (`0` when `min_txid == 1`).
    pub pre_apply_checksum: u64,
}

impl LtxHeader {
    /// Validates header invariants.
    pub fn validate(&self) -> Result<(), LtxError> {
        if !(512..=65_536).contains(&self.page_size) || !self.page_size.is_power_of_two() {
            return Err(LtxError::InvalidPageSize(self.page_size));
        }
        if self.min_txid == 0 || self.min_txid > self.max_txid {
            return Err(LtxError::InvalidTxidRange {
                min: self.min_txid,
                max: self.max_txid,
            });
        }
        Ok(())
    }

    /// Serializes this header into a fixed 100-byte big-endian buffer.
    pub fn encode(&self) -> Result<[u8; LTX_HEADER_SIZE], LtxError> {
        self.validate()?;
        let mut buf = [0u8; LTX_HEADER_SIZE];
        buf[0..4].copy_from_slice(LTX_MAGIC);
        buf[4..8].copy_from_slice(&self.flags.to_be_bytes());
        buf[8..12].copy_from_slice(&self.page_size.to_be_bytes());
        buf[12..16].copy_from_slice(&self.commit.to_be_bytes());
        buf[16..24].copy_from_slice(&self.min_txid.to_be_bytes());
        buf[24..32].copy_from_slice(&self.max_txid.to_be_bytes());
        buf[32..40].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        buf[40..48].copy_from_slice(&self.pre_apply_checksum.to_be_bytes());
        Ok(buf)
    }

    /// Decodes and validates a 100-byte big-endian LTX1 header.
    pub fn decode(buf: &[u8]) -> Result<Self, LtxError> {
        if buf.len() < LTX_HEADER_SIZE {
            return Err(LtxError::Truncated);
        }
        if &buf[0..4] != LTX_MAGIC {
            return Err(LtxError::InvalidMagic);
        }
        let header = Self {
            flags: read_be_u32(&buf[4..8])?,
            page_size: read_be_u32(&buf[8..12])?,
            commit: read_be_u32(&buf[12..16])?,
            min_txid: read_be_u64(&buf[16..24])?,
            max_txid: read_be_u64(&buf[24..32])?,
            timestamp_ms: i64::from_be_bytes(
                buf[32..40].try_into().map_err(|_| LtxError::Truncated)?,
            ),
            pre_apply_checksum: read_be_u64(&buf[40..48])?,
        };
        header.validate()?;
        Ok(header)
    }
}

/// One sorted page frame (`pgno` is 1-based SQLite page number).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtxPageFrame {
    /// 1-based SQLite page number (`1..=header.commit`).
    pub pgno: u32,
    /// Raw SQLite page bytes (`len == header.page_size`).
    pub data: Vec<u8>,
}

/// 16-byte Litestream `"LTX1"` trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtxTrailer {
    /// Rolling database checksum after applying all frames in this file.
    pub post_apply_checksum: u64,
    /// CRC-64/ISO checksum over all preceding bytes in this file (with MSB flag set).
    pub file_checksum: u64,
}

/// Decoded `"LTX1"` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtxDocument {
    /// 100-byte header.
    pub header: LtxHeader,
    /// Sorted page frames.
    pub pages: Vec<LtxPageFrame>,
    /// Verified 16-byte trailer.
    pub trailer: LtxTrailer,
}

fn read_be_u32(slice: &[u8]) -> Result<u32, LtxError> {
    slice
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| LtxError::Truncated)
}

fn read_be_u64(slice: &[u8]) -> Result<u64, LtxError> {
    slice
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| LtxError::Truncated)
}

/// Encodes an `"LTX1"` document (100B header + sorted frames + 4B zero sentinel + 16B trailer).
pub fn encode_ltx(
    header: &LtxHeader,
    pages: &[LtxPageFrame],
    post_apply_checksum: u64,
) -> Result<(Vec<u8>, LtxTrailer), LtxError> {
    let hdr_bytes = header.encode()?;
    let ps = header.page_size as usize;
    let mut prev = 0u32;
    for f in pages {
        if f.pgno == 0 || f.pgno <= prev || f.pgno > header.commit {
            return Err(LtxError::InvalidPageOrder { pgno: f.pgno });
        }
        if f.data.len() != ps {
            return Err(LtxError::PageSizeMismatch {
                expected: header.page_size,
                actual: f.data.len(),
            });
        }
        prev = f.pgno;
    }

    let mut out =
        Vec::with_capacity(LTX_HEADER_SIZE + pages.len() * (4 + ps) + 4 + LTX_TRAILER_SIZE);
    out.extend_from_slice(&hdr_bytes);
    for f in pages {
        out.extend_from_slice(&f.pgno.to_be_bytes());
        out.extend_from_slice(&f.data);
    }
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&post_apply_checksum.to_be_bytes());
    let file_checksum = crc64_iso(&out) | LTX_CHECKSUM_FLAG;
    out.extend_from_slice(&file_checksum.to_be_bytes());
    Ok((
        out,
        LtxTrailer {
            post_apply_checksum,
            file_checksum,
        },
    ))
}

/// Decodes and CRC-64-verifies an `"LTX1"` binary payload.
pub fn decode_ltx(bytes: &[u8]) -> Result<LtxDocument, LtxError> {
    if bytes.len() < LTX_HEADER_SIZE + 4 + LTX_TRAILER_SIZE {
        return Err(LtxError::Truncated);
    }
    let header = LtxHeader::decode(bytes)?;
    let t_start = bytes.len() - LTX_TRAILER_SIZE;
    let post_apply_checksum = read_be_u64(&bytes[t_start..t_start + 8])?;
    let file_checksum = read_be_u64(&bytes[t_start + 8..bytes.len()])?;
    if file_checksum != (crc64_iso(&bytes[..bytes.len() - 8]) | LTX_CHECKSUM_FLAG) {
        return Err(LtxError::FileChecksumMismatch);
    }

    let ps = header.page_size as usize;
    let (mut cursor, mut prev, mut terminated) = (LTX_HEADER_SIZE, 0u32, false);
    let mut pages = Vec::new();
    while cursor + 4 <= t_start {
        let pgno = read_be_u32(&bytes[cursor..cursor + 4])?;
        cursor += 4;
        if pgno == 0 {
            terminated = true;
            break;
        }
        if pgno <= prev || pgno > header.commit {
            return Err(LtxError::InvalidPageOrder { pgno });
        }
        let end = cursor.checked_add(ps).ok_or(LtxError::Truncated)?;
        if end > t_start {
            return Err(LtxError::Truncated);
        }
        pages.push(LtxPageFrame {
            pgno,
            data: bytes[cursor..end].to_vec(),
        });
        prev = pgno;
        cursor = end;
    }
    if !terminated || cursor != t_start {
        return Err(LtxError::Truncated);
    }
    Ok(LtxDocument {
        header,
        pages,
        trailer: LtxTrailer {
            post_apply_checksum,
            file_checksum,
        },
    })
}

/// Encodes a complete raw SQLite database file as a full `"LTX1"` snapshot (`min_txid = 1`).
pub fn encode_snapshot_ltx(
    raw_db: &[u8],
    page_size: u32,
    max_txid: u64,
    timestamp_ms: i64,
) -> Result<(Vec<u8>, LtxHeader, LtxTrailer), LtxError> {
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(LtxError::InvalidPageSize(page_size));
    }
    let ps = page_size as usize;
    if !raw_db.len().is_multiple_of(ps) {
        return Err(LtxError::PageSizeMismatch {
            expected: page_size,
            actual: raw_db.len() % ps,
        });
    }
    let commit = u32::try_from(raw_db.len() / ps).map_err(|_| LtxError::Truncated)?;
    let pages: Vec<LtxPageFrame> = raw_db
        .chunks_exact(ps)
        .enumerate()
        .map(|(idx, chunk)| LtxPageFrame {
            pgno: (idx as u32) + 1,
            data: chunk.to_vec(),
        })
        .collect();
    let post = compute_db_checksum(pages.iter().map(|p| (p.pgno, p.data.as_slice())));
    let header = LtxHeader {
        flags: 0,
        page_size,
        commit,
        min_txid: 1,
        max_txid: max_txid.max(1),
        timestamp_ms,
        pre_apply_checksum: 0,
    };
    let (encoded, trailer) = encode_ltx(&header, &pages, post)?;
    Ok((encoded, header, trailer))
}

/// Reconstructs raw SQLite database bytes from a full `"LTX1"` snapshot and verifies `post_apply_checksum`.
pub fn reconstruct_db_from_ltx(doc: &LtxDocument) -> Result<Vec<u8>, LtxError> {
    let ps = doc.header.page_size as usize;
    let count = doc.header.commit as usize;
    if doc.pages.len() != count {
        return Err(LtxError::Truncated);
    }
    let mut raw = vec![0u8; count.saturating_mul(ps)];
    for (idx, f) in doc.pages.iter().enumerate() {
        if f.pgno != (idx as u32) + 1 {
            return Err(LtxError::InvalidPageOrder { pgno: f.pgno });
        }
        raw[idx * ps..(idx + 1) * ps].copy_from_slice(&f.data);
    }
    let computed = compute_db_checksum(doc.pages.iter().map(|p| (p.pgno, p.data.as_slice())));
    if computed != doc.trailer.post_apply_checksum {
        return Err(LtxError::PostApplyChecksumMismatch);
    }
    Ok(raw)
}
