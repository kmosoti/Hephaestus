//! Constant-time SPKI SHA-256 certificate pin extraction and comparison helpers.

use sha2::{Digest, Sha256};

/// Constant-time comparison of two 32-byte SHA-256 digests.
#[must_use]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    core::hint::black_box(diff) == 0
}

/// Constant-time membership check scanning the full allowlist without short-circuiting.
#[must_use]
pub(crate) fn ct_contains_pin(allowed: &[[u8; 32]], actual: &[u8; 32]) -> bool {
    let mut matched = 0u8;
    for fp in allowed {
        matched |= u8::from(ct_eq_32(fp, actual));
    }
    core::hint::black_box(matched) != 0
}

struct DerTlv<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
    rest: &'a [u8],
}

fn read_der_tlv(input: &[u8]) -> Result<DerTlv<'_>, &'static str> {
    let &tag = input.first().ok_or("truncated DER tag")?;
    let &len_b = input.get(1).ok_or("truncated DER len")?;
    let (val_len, hdr_len) = if (len_b & 0x80) == 0 {
        (len_b as usize, 2usize)
    } else {
        let count = (len_b & 0x7F) as usize;
        if count == 0 || count > 4 || input.len() < 2 + count {
            return Err("invalid DER length encoding");
        }
        let mut len = 0usize;
        for &b in &input[2..2 + count] {
            len = (len << 8) | (b as usize);
        }
        (len, 2 + count)
    };
    let end = hdr_len.checked_add(val_len).ok_or("DER length overflow")?;
    if end > input.len() {
        return Err("DER element exceeds buffer");
    }
    Ok(DerTlv {
        tag,
        full: &input[..end],
        value: &input[hdr_len..end],
        rest: &input[end..],
    })
}

/// Extracts the exact SubjectPublicKeyInfo (SPKI) DER TLV from an X.509 v3 certificate DER.
pub fn extract_spki_der(cert_der: &[u8]) -> Result<&[u8], &'static str> {
    let cert = read_der_tlv(cert_der)?;
    if cert.tag != 0x30 {
        return Err("certificate is not a DER SEQUENCE");
    }
    let tbs_tlv = read_der_tlv(cert.value)?;
    if tbs_tlv.tag != 0x30 {
        return Err("tbsCertificate is not a DER SEQUENCE");
    }
    let mut tbs = tbs_tlv.value;
    if tbs.first() == Some(&0xA0) {
        tbs = read_der_tlv(tbs)?.rest;
    }
    for _ in 0..5 {
        tbs = read_der_tlv(tbs)?.rest;
    }
    let spki = read_der_tlv(tbs)?;
    if spki.tag != 0x30 {
        return Err("subjectPublicKeyInfo is not a DER SEQUENCE");
    }
    Ok(spki.full)
}

/// Computes the RFC 7469 SHA-256 pin of an X.509 certificate's SubjectPublicKeyInfo (SPKI).
pub fn spki_sha256_pin(cert_der: &[u8]) -> Result<[u8; 32], &'static str> {
    let spki = extract_spki_der(cert_der)?;
    Ok(Sha256::digest(spki).into())
}
