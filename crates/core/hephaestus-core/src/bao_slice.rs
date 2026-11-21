//! Bao slice proof extraction and verified streaming decoding helpers.

use crate::bao::{
    BAO_CHUNK_LEN, BAO_PARENT_LEN, BaoError, chunk_byte_len, chunk_count, leaf_hash,
    left_subtree_chunks, parent_hash, read_parent, read_u64_le,
};
use crate::cas::BlobDigest;
use alloc::vec::Vec;

#[derive(Clone, Copy)]
struct SliceRange {
    total_len: u64,
    start_chunk: u64,
    end_chunk: u64,
}

impl SliceRange {
    const fn overlaps(self, first_chunk: u64, chunks: u64) -> bool {
        let sub_end = first_chunk.saturating_add(chunks);
        first_chunk < self.end_chunk && sub_end > self.start_chunk
    }
}

fn validate_slice(total_len: u64, start: u64, len: u64) -> Result<SliceRange, BaoError> {
    let end = start.checked_add(len).ok_or(BaoError::SliceOutOfBounds {
        start,
        len,
        total_len,
    })?;
    if end > total_len {
        return Err(BaoError::SliceOutOfBounds {
            start,
            len,
            total_len,
        });
    }
    let (start_chunk, end_chunk) = if len == 0 {
        let idx = (start / BAO_CHUNK_LEN as u64).min(chunk_count(total_len) - 1);
        (idx, idx + 1)
    } else {
        (
            start / BAO_CHUNK_LEN as u64,
            end.div_ceil(BAO_CHUNK_LEN as u64),
        )
    };
    Ok(SliceRange {
        total_len,
        start_chunk,
        end_chunk,
    })
}

struct ExtractCtx<'a> {
    data: &'a [u8],
    outboard: &'a [u8],
    cursor: usize,
    range: SliceRange,
    out: Vec<u8>,
}

impl ExtractCtx<'_> {
    fn walk(&mut self, first_chunk: u64, chunks: u64) -> Result<(), BaoError> {
        if chunks == 1 {
            let start = (first_chunk as usize).saturating_mul(BAO_CHUNK_LEN);
            let len = chunk_byte_len(self.range.total_len, first_chunk);
            let slice = self
                .data
                .get(start..start + len)
                .ok_or(BaoError::Truncated)?;
            self.out.extend_from_slice(slice);
            return Ok(());
        }
        let (l_cv, r_cv) = read_parent(self.outboard, &mut self.cursor)?;
        self.out.extend_from_slice(&l_cv);
        self.out.extend_from_slice(&r_cv);
        let left_c = left_subtree_chunks(chunks);
        let right_c = chunks - left_c;
        if self.range.overlaps(first_chunk, left_c) {
            self.walk(first_chunk, left_c)?;
        } else {
            self.cursor = self
                .cursor
                .checked_add((left_c.saturating_sub(1) as usize) * BAO_PARENT_LEN)
                .ok_or(BaoError::Truncated)?;
        }
        if self.range.overlaps(first_chunk + left_c, right_c) {
            self.walk(first_chunk + left_c, right_c)?;
        } else {
            self.cursor = self
                .cursor
                .checked_add((right_c.saturating_sub(1) as usize) * BAO_PARENT_LEN)
                .ok_or(BaoError::Truncated)?;
        }
        Ok(())
    }
}

/// Extracts a compact verifiable proof slice for `[start..start + len)` from `data` + `outboard`.
pub fn extract_slice_from_outboard(
    data: &[u8],
    outboard: &[u8],
    start: u64,
    len: u64,
) -> Result<Vec<u8>, BaoError> {
    let mut cursor = 0usize;
    let total_len = read_u64_le(outboard, &mut cursor)?;
    if total_len != data.len() as u64 {
        return Err(BaoError::InvalidEncoding);
    }
    let range = validate_slice(total_len, start, len)?;
    let mut ctx = ExtractCtx {
        data,
        outboard,
        cursor,
        range,
        out: total_len.to_le_bytes().to_vec(),
    };
    ctx.walk(0, chunk_count(total_len))?;
    if ctx.cursor != outboard.len() {
        return Err(BaoError::InvalidEncoding);
    }
    Ok(ctx.out)
}

struct VerifyCtx<'a> {
    slice_bytes: &'a [u8],
    cursor: usize,
    range: SliceRange,
    decoded: Vec<u8>,
}

impl VerifyCtx<'_> {
    fn walk(
        &mut self,
        expected_cv: &[u8; 32],
        first_chunk: u64,
        chunks: u64,
    ) -> Result<(), BaoError> {
        if chunks == 1 {
            let len = chunk_byte_len(self.range.total_len, first_chunk);
            let end = self.cursor.checked_add(len).ok_or(BaoError::Truncated)?;
            let chunk = self
                .slice_bytes
                .get(self.cursor..end)
                .ok_or(BaoError::Truncated)?;
            self.cursor = end;
            if &leaf_hash(first_chunk, chunk) != expected_cv {
                return Err(BaoError::HashMismatch);
            }
            self.decoded.extend_from_slice(chunk);
            return Ok(());
        }
        let (l_cv, r_cv) = read_parent(self.slice_bytes, &mut self.cursor)?;
        if &parent_hash(&l_cv, &r_cv) != expected_cv {
            return Err(BaoError::HashMismatch);
        }
        let left_c = left_subtree_chunks(chunks);
        let right_c = chunks - left_c;
        if self.range.overlaps(first_chunk, left_c) {
            self.walk(&l_cv, first_chunk, left_c)?;
        }
        if self.range.overlaps(first_chunk + left_c, right_c) {
            self.walk(&r_cv, first_chunk + left_c, right_c)?;
        }
        Ok(())
    }
}

/// Verifies an inboard stream against `expected_root` and returns the full plaintext payload.
pub fn decode_inboard(encoded: &[u8], expected_root: &BlobDigest) -> Result<Vec<u8>, BaoError> {
    let mut cursor = 0usize;
    let total_len = read_u64_le(encoded, &mut cursor)?;
    verify_and_decode_slice(encoded, expected_root, 0, total_len)
}

/// Verifies a compact Bao slice proof against `expected_root` without downloading the full blob,
/// returning the exact requested `[start..start + len)` bytes.
pub fn verify_and_decode_slice(
    slice_bytes: &[u8],
    expected_root: &BlobDigest,
    start: u64,
    len: u64,
) -> Result<Vec<u8>, BaoError> {
    let mut cursor = 0usize;
    let total_len = read_u64_le(slice_bytes, &mut cursor)?;
    let range = validate_slice(total_len, start, len)?;
    let mut ctx = VerifyCtx {
        slice_bytes,
        cursor,
        range,
        decoded: Vec::new(),
    };
    ctx.walk(expected_root.as_bytes(), 0, chunk_count(total_len))?;
    if ctx.cursor != slice_bytes.len() {
        return Err(BaoError::InvalidEncoding);
    }
    let trim_start = (start - range.start_chunk * BAO_CHUNK_LEN as u64) as usize;
    let trim_end = trim_start
        .checked_add(len as usize)
        .ok_or(BaoError::InvalidEncoding)?;
    ctx.decoded
        .get(trim_start..trim_end)
        .map(<[u8]>::to_vec)
        .ok_or(BaoError::InvalidEncoding)
}
