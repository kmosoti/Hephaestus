//! Pure `#![no_std]` FastCDC content-defined chunking with normalized Gearhash masks.

use crate::cas::BlobDigest;
use alloc::vec::Vec;

/// Minimum chunk size emitted by default FastCDC (8 KiB).
pub const FASTCDC_MIN_CHUNK: usize = 8 * 1024;
/// Target average chunk size emitted by default FastCDC (32 KiB).
pub const FASTCDC_AVG_CHUNK: usize = 32 * 1024;
/// Maximum chunk size emitted by default FastCDC (128 KiB).
pub const FASTCDC_MAX_CHUNK: usize = 128 * 1024;

/// Stricter mask (17 bits set) used in `[min_size..avg_size)` to suppress tiny chunks.
pub const FASTCDC_MASK_S: u64 = 0x0007_D907_0353_0000;
/// Looser mask (13 bits set) used in `[avg_size..max_size)` to cap long chunks near `avg_size`.
pub const FASTCDC_MASK_L: u64 = 0x0000_D903_0353_0000;

/// Deterministic 256-entry 64-bit Gearhash lookup table generated at compile time.
pub const GEAR_TABLE: [u64; 256] = generate_gear_table();

const fn generate_gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut state: u64 = 0x517C_C1B7_2722_0A95;
    let mut i = 0usize;
    while i < 256 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        table[i] = z ^ (z >> 31);
        i += 1;
    }
    table
}

/// Configuration parameters for normalized FastCDC chunking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastCdcConfig {
    /// Minimum chunk length in bytes (for non-final chunks).
    pub min_size: usize,
    /// Target average chunk length in bytes (normalized cutover point).
    pub avg_size: usize,
    /// Hard maximum chunk length in bytes.
    pub max_size: usize,
    /// Rolling Gearhash mask applied below `avg_size`.
    pub mask_s: u64,
    /// Rolling Gearhash mask applied at or above `avg_size`.
    pub mask_l: u64,
}

impl Default for FastCdcConfig {
    fn default() -> Self {
        Self {
            min_size: FASTCDC_MIN_CHUNK,
            avg_size: FASTCDC_AVG_CHUNK,
            max_size: FASTCDC_MAX_CHUNK,
            mask_s: FASTCDC_MASK_S,
            mask_l: FASTCDC_MASK_L,
        }
    }
}

impl FastCdcConfig {
    /// Computes normalized masks for a power-of-two `avg_size` (with normalization level 2).
    #[must_use]
    pub const fn for_bounds(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        let bits = avg_size.trailing_zeros();
        let mask_s = spread_mask(bits.saturating_add(2));
        let mask_l = spread_mask(bits.saturating_sub(2));
        Self {
            min_size,
            avg_size,
            max_size,
            mask_s,
            mask_l,
        }
    }
}

const fn spread_mask(bit_count: u32) -> u64 {
    let clamped = if bit_count > 48 { 48 } else { bit_count };
    let mut mask = 0u64;
    let mut i = 0u32;
    while i < clamped {
        // Place bits in upper/mid bit positions [16..64) so shifted Gearhash mixes well.
        mask |= 1u64 << (16 + i);
        i += 1;
    }
    mask
}

/// A single content-defined chunk boundary and its BLAKE3 content digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdcChunk {
    /// Byte offset inside the original buffer.
    pub offset: usize,
    /// Byte length of this chunk.
    pub len: usize,
    /// BLAKE3 digest of `data[offset..offset + len]`.
    pub hash: BlobDigest,
}

/// Computes the next FastCDC cut length within `data` using normalized chunking.
#[must_use]
pub fn next_chunk_len(data: &[u8], cfg: FastCdcConfig) -> usize {
    let n = data.len();
    if n <= cfg.min_size {
        return n;
    }
    let max_len = n.min(cfg.max_size.max(cfg.min_size));
    let normal_size = cfg.avg_size.clamp(cfg.min_size, max_len);
    let mut fp: u64 = 0;

    let mut i = cfg.min_size;
    while i < normal_size {
        fp = (fp << 1).wrapping_add(GEAR_TABLE[data[i] as usize]);
        if (fp & cfg.mask_s) == 0 {
            return i + 1;
        }
        i += 1;
    }

    while i < max_len {
        fp = (fp << 1).wrapping_add(GEAR_TABLE[data[i] as usize]);
        if (fp & cfg.mask_l) == 0 {
            return i + 1;
        }
        i += 1;
    }
    max_len
}

/// Splits `data` into content-defined chunks using the default `8 KiB / 32 KiB / 128 KiB` profile.
#[must_use]
pub fn chunk_bytes(data: &[u8]) -> Vec<CdcChunk> {
    chunk_bytes_with_config(data, FastCdcConfig::default())
}

/// Splits `data` into content-defined chunks using an explicit [`FastCdcConfig`].
#[must_use]
pub fn chunk_bytes_with_config(data: &[u8], cfg: FastCdcConfig) -> Vec<CdcChunk> {
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let len = next_chunk_len(&data[offset..], cfg);
        let slice = &data[offset..offset + len];
        chunks.push(CdcChunk {
            offset,
            len,
            hash: BlobDigest::of(slice),
        });
        offset += len;
    }
    chunks
}
