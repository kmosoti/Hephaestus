//! Framed Zstd encoding/decoding helpers for `GRNB0002` and legacy `GRNB0001` bundles.

use crate::bundler::{
    BUNDLE_MAGIC_V1, BUNDLE_MAGIC_V2, BundleError, DIR_HEADER_LEN, FRAME_DESC_LEN,
    MAX_BUNDLE_DIR_BYTES, MAX_BUNDLE_FRAMES, MAX_FRAME_COMP_BYTES, MAX_FRAME_RAW_DECODED_BYTES,
    MAX_LEGACY_V1_DECODED_BYTES, zstd_err,
};
use alloc::vec::Vec;
use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, compress};
use ruzstd::io::Read as _;

/// Descriptor for one independent Zstd frame inside a `GRNB0002` bundle directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameDesc {
    /// Uncompressed byte offset in the bundle's logical payload space.
    pub raw_offset: u64,
    /// Uncompressed byte length of this frame.
    pub raw_len: u32,
    /// Compressed byte offset inside the `GRNB0002` object.
    pub comp_offset: u64,
    /// Compressed byte length of this Zstd frame.
    pub comp_len: u32,
}

impl FrameDesc {
    pub(crate) fn write_to(&self, dst: &mut [u8]) {
        dst[0..8].copy_from_slice(&self.raw_offset.to_le_bytes());
        dst[8..12].copy_from_slice(&self.raw_len.to_le_bytes());
        dst[12..20].copy_from_slice(&self.comp_offset.to_le_bytes());
        dst[20..24].copy_from_slice(&self.comp_len.to_le_bytes());
    }

    pub(crate) fn read_from(src: &[u8]) -> Option<Self> {
        Some(Self {
            raw_offset: u64::from_le_bytes(src.get(0..8)?.try_into().ok()?),
            raw_len: u32::from_le_bytes(src.get(8..12)?.try_into().ok()?),
            comp_offset: u64::from_le_bytes(src.get(12..20)?.try_into().ok()?),
            comp_len: u32::from_le_bytes(src.get(20..24)?.try_into().ok()?),
        })
    }
}

/// Parsed `GRNB0002` frame directory header enabling bounded HTTP/object range reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleDirectoryHeader {
    /// Total number of independent Zstd frames in the bundle.
    pub frame_count: usize,
    /// Total byte size of the leading directory header (`12 + frame_count * 24`).
    pub dir_len: usize,
    /// Ordered frame descriptors sorted ascending by `raw_offset`.
    pub frames: Vec<FrameDesc>,
}

impl BundleDirectoryHeader {
    /// Locates the single Zstd frame containing `[byte_offset..byte_offset + byte_len]`
    /// and returns `(frame_desc, local_offset_within_frame)`.
    pub fn find_frame_for_slice(
        &self,
        byte_offset: u64,
        byte_len: u32,
    ) -> Result<(FrameDesc, usize), BundleError> {
        let last = self.frames.last().ok_or(BundleError::InvalidFormat)?;
        let total = usize::try_from(
            last.raw_offset
                .checked_add(u64::from(last.raw_len))
                .ok_or(BundleError::InvalidFormat)?,
        )
        .unwrap_or(usize::MAX);
        let (offset, len) = (
            usize::try_from(byte_offset).unwrap_or(usize::MAX),
            byte_len as usize,
        );

        let (mut lo, mut hi) = (0usize, self.frames.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.frames[mid].raw_offset <= byte_offset {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let frame_idx = lo.checked_sub(1).ok_or_else(|| oob(offset, len, total))?;
        let frame = self.frames[frame_idx];
        let local_off =
            usize::try_from(byte_offset - frame.raw_offset).map_err(|_| oob(offset, len, total))?;
        let local_end = local_off
            .checked_add(len)
            .ok_or_else(|| oob(offset, len, total))?;
        if local_end > frame.raw_len as usize {
            return Err(oob(offset, len, total));
        }
        if frame.comp_offset < self.dir_len as u64
            || frame.raw_len as usize > MAX_FRAME_RAW_DECODED_BYTES
            || frame.comp_len as usize > MAX_FRAME_COMP_BYTES
        {
            return Err(BundleError::InvalidFormat);
        }
        Ok((frame, local_off))
    }
}

pub(crate) fn oob(offset: usize, len: usize, total: usize) -> BundleError {
    BundleError::SliceOutOfBounds { offset, len, total }
}

pub(crate) fn encode_frame(dst: &mut Vec<u8>, raw_frame: &[u8]) -> Result<(u64, u32), BundleError> {
    let comp_offset = dst.len() as u64;
    compress(raw_frame, &mut *dst, CompressionLevel::Fastest);
    let comp_len =
        u32::try_from(dst.len() as u64 - comp_offset).map_err(|_| BundleError::InvalidFormat)?;
    Ok((comp_offset, comp_len))
}

/// Returns the number of independent Zstd frames in a `GRNB0002` bundle, or `None` otherwise.
#[must_use]
pub fn bundle_frame_count(compressed_bytes: &[u8]) -> Option<usize> {
    if compressed_bytes.len() < DIR_HEADER_LEN || &compressed_bytes[0..8] != BUNDLE_MAGIC_V2 {
        return None;
    }
    Some(u32::from_le_bytes(compressed_bytes[8..12].try_into().ok()?) as usize)
}

/// Parses a leading `GRNB0002` prefix buffer into a [`BundleDirectoryHeader`].
///
/// Returns [`BundleError::TruncatedDirectory`] with the exact required prefix length when the
/// caller's initial range probe was shorter than the frame directory.
pub fn parse_frame_directory_header(prefix: &[u8]) -> Result<BundleDirectoryHeader, BundleError> {
    let frame_count = bundle_frame_count(prefix).ok_or(BundleError::InvalidFormat)?;
    if frame_count == 0 || frame_count > MAX_BUNDLE_FRAMES {
        return Err(BundleError::InvalidFormat);
    }
    let dir_len = frame_count
        .checked_mul(FRAME_DESC_LEN)
        .and_then(|n| n.checked_add(DIR_HEADER_LEN))
        .ok_or(BundleError::InvalidFormat)?;
    if dir_len > MAX_BUNDLE_DIR_BYTES {
        return Err(BundleError::InvalidFormat);
    }
    if prefix.len() < dir_len {
        return Err(BundleError::TruncatedDirectory {
            required_bytes: dir_len,
        });
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(frame_count)
        .map_err(|_| BundleError::InvalidFormat)?;
    let mut expected_raw_offset = 0u64;
    let mut min_comp_offset = dir_len as u64;
    for idx in 0..frame_count {
        let desc = read_frame_desc(prefix, idx)?;
        if desc.raw_len as usize > MAX_FRAME_RAW_DECODED_BYTES
            || desc.comp_len as usize > MAX_FRAME_COMP_BYTES
            || desc.raw_offset < expected_raw_offset
            || desc.comp_offset < min_comp_offset
        {
            return Err(BundleError::InvalidFormat);
        }
        expected_raw_offset = desc
            .raw_offset
            .checked_add(u64::from(desc.raw_len))
            .ok_or(BundleError::InvalidFormat)?;
        min_comp_offset = desc
            .comp_offset
            .checked_add(u64::from(desc.comp_len))
            .ok_or(BundleError::InvalidFormat)?;
        frames.push(desc);
    }
    Ok(BundleDirectoryHeader {
        frame_count,
        dir_len,
        frames,
    })
}

pub(crate) fn write_frame_desc(buf: &mut [u8], frame_idx: usize, desc: FrameDesc) {
    let start = DIR_HEADER_LEN + frame_idx * FRAME_DESC_LEN;
    desc.write_to(&mut buf[start..start + FRAME_DESC_LEN]);
}

fn read_frame_desc(buf: &[u8], frame_idx: usize) -> Result<FrameDesc, BundleError> {
    let start = DIR_HEADER_LEN + frame_idx * FRAME_DESC_LEN;
    FrameDesc::read_from(
        buf.get(start..start + FRAME_DESC_LEN)
            .ok_or(BundleError::InvalidFormat)?,
    )
    .ok_or(BundleError::InvalidFormat)
}

fn decode_zstd_frame(
    frame_bytes: &[u8],
    expected_raw_len: Option<usize>,
) -> Result<Vec<u8>, BundleError> {
    let limit = match expected_raw_len {
        Some(n) if n > MAX_FRAME_RAW_DECODED_BYTES => return Err(BundleError::InvalidFormat),
        Some(n) => n,
        None => MAX_LEGACY_V1_DECODED_BYTES,
    };
    let decoder = StreamingDecoder::new(frame_bytes).map_err(zstd_err)?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    let mut reader = decoder.take((limit as u64) + 1);
    loop {
        let n = reader.read(&mut chunk).map_err(zstd_err)?;
        if n == 0 {
            break;
        }
        if raw.len().saturating_add(n) > limit {
            return Err(BundleError::InvalidFormat);
        }
        raw.try_reserve(n).map_err(|_| BundleError::InvalidFormat)?;
        raw.extend_from_slice(&chunk[..n]);
    }
    if let Some(expected) = expected_raw_len
        && raw.len() != expected
    {
        return Err(BundleError::InvalidFormat);
    }
    Ok(raw)
}

fn verify_slice(
    raw: &[u8],
    start: usize,
    end: usize,
    expected_hash: &[u8; 32],
) -> Result<Vec<u8>, BundleError> {
    let slice = &raw[start..end];
    if blake3::hash(slice).as_bytes() != expected_hash {
        return Err(BundleError::ChecksumMismatch);
    }
    Ok(slice.to_vec())
}

/// Decompresses a single range-fetched Zstd frame, extracts `[local_offset..+byte_len]`,
/// and verifies its BLAKE3 content digest.
pub fn unpack_blob_from_frame(
    compressed_frame: &[u8],
    frame: &FrameDesc,
    local_offset: usize,
    byte_len: u32,
    expected_hash: &[u8; 32],
) -> Result<Vec<u8>, BundleError> {
    if frame.raw_len as usize > MAX_FRAME_RAW_DECODED_BYTES
        || frame.comp_len as usize > MAX_FRAME_COMP_BYTES
        || compressed_frame.len() != frame.comp_len as usize
    {
        return Err(BundleError::InvalidFormat);
    }
    let local_end = local_offset
        .checked_add(byte_len as usize)
        .ok_or_else(|| oob(local_offset, byte_len as usize, frame.raw_len as usize))?;
    if local_end > frame.raw_len as usize {
        return Err(oob(local_offset, byte_len as usize, frame.raw_len as usize));
    }
    let frame_raw = decode_zstd_frame(compressed_frame, Some(frame.raw_len as usize))?;
    verify_slice(&frame_raw, local_offset, local_end, expected_hash)
}

fn unpack_v2(
    compressed_bytes: &[u8],
    expected_hash: &[u8; 32],
    byte_offset: u64,
    byte_len: u32,
) -> Result<Vec<u8>, BundleError> {
    let dir = parse_frame_directory_header(compressed_bytes).map_err(|e| match e {
        BundleError::TruncatedDirectory { .. } => BundleError::InvalidFormat,
        other => other,
    })?;
    let (frame, local_off) = dir.find_frame_for_slice(byte_offset, byte_len)?;
    let comp_start = usize::try_from(frame.comp_offset).map_err(|_| BundleError::InvalidFormat)?;
    let comp_end = comp_start
        .checked_add(frame.comp_len as usize)
        .ok_or(BundleError::InvalidFormat)?;
    if comp_start < dir.dir_len || comp_end > compressed_bytes.len() {
        return Err(BundleError::InvalidFormat);
    }
    unpack_blob_from_frame(
        &compressed_bytes[comp_start..comp_end],
        &frame,
        local_off,
        byte_len,
        expected_hash,
    )
}

fn unpack_v1(
    compressed_bytes: &[u8],
    expected_hash: &[u8; 32],
    byte_offset: u64,
    byte_len: u32,
) -> Result<Vec<u8>, BundleError> {
    let raw = decode_zstd_frame(compressed_bytes, None)?;
    if raw.len() < DIR_HEADER_LEN || &raw[0..8] != BUNDLE_MAGIC_V1 {
        return Err(BundleError::InvalidFormat);
    }
    let offset =
        usize::try_from(byte_offset).map_err(|_| oob(usize::MAX, byte_len as usize, raw.len()))?;
    let len = byte_len as usize;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| oob(offset, len, raw.len()))?;
    if end > raw.len() {
        return Err(oob(offset, len, raw.len()));
    }
    verify_slice(&raw, offset, end, expected_hash)
}

/// Decompresses the containing Zstd frame (`GRNB0002`) or legacy stream (`GRNB0001`),
/// slices `[byte_offset..byte_offset + byte_len]`, and verifies its BLAKE3 digest.
pub fn unpack_blob_from_bundle(
    compressed_bytes: &[u8],
    expected_hash: &[u8; 32],
    byte_offset: u64,
    byte_len: u32,
) -> Result<Vec<u8>, BundleError> {
    if compressed_bytes.len() >= 8 && &compressed_bytes[0..8] == BUNDLE_MAGIC_V2 {
        unpack_v2(compressed_bytes, expected_hash, byte_offset, byte_len)
    } else {
        unpack_v1(compressed_bytes, expected_hash, byte_offset, byte_len)
    }
}
