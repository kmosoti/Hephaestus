#![forbid(unsafe_code)]
//! Deterministic tests for Wave 1 pure `#![no_std]` primitives: FastCDC, Bao verified streaming,
//! BLAKE3 MMR inclusion proofs, RFC 8785 JCS canonicalization, LTX1 wire format, and range unpacking.

use hephaestus_core::{
    BaoError, BlobDigest, BundleAccumulator, BundleError, ChainError, ChangeId, CommitId,
    FASTCDC_AVG_CHUNK, FASTCDC_MASK_L, FASTCDC_MASK_S, FASTCDC_MAX_CHUNK, FASTCDC_MIN_CHUNK,
    LTX_HEADER_SIZE, LTX_MAGIC, LtxError, Mmr, ObservationDraft, ObservationKind, OpId,
    append_observation_in_memory, canonicalize_json, chunk_bytes, compute_observation_hash,
    crc64_iso, decode_inboard, decode_ltx, encode_inboard, encode_outboard, encode_snapshot_ltx,
    extract_slice_from_outboard, observation_chain_mmr, parse_frame_directory_header,
    reconstruct_db_from_ltx, unpack_blob_from_frame, verify_and_decode_slice,
    verify_inclusion_proof, verify_observation_chain,
};
use std::collections::BTreeSet;

fn prng_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.push((state >> 33) as u8);
    }
    out
}

#[test]
fn fastcdc_deterministic_bounds_and_shift_resilience() {
    assert_eq!(FASTCDC_MASK_S.count_ones(), 17);
    assert_eq!(FASTCDC_MASK_L.count_ones(), 13);
    assert!(chunk_bytes(&[]).is_empty());

    let small = prng_bytes(1024, 7);
    let small_chunks = chunk_bytes(&small);
    assert_eq!(small_chunks.len(), 1);
    assert_eq!(small_chunks[0].len, 1024);

    let data = prng_bytes(512 * 1024, 0xCAFE_BABE);
    let c1 = chunk_bytes(&data);
    let c2 = chunk_bytes(&data);
    assert_eq!(c1, c2);
    assert!(c1.len() >= 4);

    let mut reassembled = Vec::with_capacity(data.len());
    for (idx, ch) in c1.iter().enumerate() {
        assert_eq!(ch.offset, reassembled.len());
        if idx + 1 < c1.len() {
            assert!(ch.len >= FASTCDC_MIN_CHUNK && ch.len <= FASTCDC_MAX_CHUNK);
        } else {
            assert!(ch.len <= FASTCDC_MAX_CHUNK);
        }
        reassembled.extend_from_slice(&data[ch.offset..ch.offset + ch.len]);
    }
    assert_eq!(reassembled, data);
    let avg = data.len() / c1.len();
    assert!(
        (FASTCDC_MIN_CHUNK..=FASTCDC_MAX_CHUNK).contains(&avg),
        "average chunk size {avg} outside expected bounds around {FASTCDC_AVG_CHUNK}"
    );

    // Prepend 137 bytes and verify content-defined deduplication preserves most downstream chunks.
    let mut shifted = prng_bytes(137, 99);
    shifted.extend_from_slice(&data);
    let c_shifted = chunk_bytes(&shifted);
    let orig_hashes: BTreeSet<[u8; 32]> = c1.iter().map(|c| c.hash.0).collect();
    let reused = c_shifted
        .iter()
        .filter(|c| orig_hashes.contains(&c.hash.0))
        .count();
    assert!(
        reused * 2 >= c1.len(),
        "expected >=50% chunk reuse after prefix insertion, got {reused}/{}",
        c1.len()
    );
}

#[test]
fn bao_outboard_inboard_slice_verification_and_tamper_rejection() {
    for &size in &[0usize, 1, 1024, 1025, 10_000, 65_536] {
        let data = prng_bytes(size, 100 + size as u64);
        let ob = encode_outboard(&data);
        let (in_root, inboard) = encode_inboard(&data);
        assert_eq!(ob.root, in_root);
        assert_eq!(decode_inboard(&inboard, &in_root).unwrap(), data);
    }

    let data = prng_bytes(64 * 1024, 42);
    let ob = encode_outboard(&data);
    let slice_start = 25_000u64;
    let slice_len = 2_500u64;
    let proof = extract_slice_from_outboard(&data, &ob.outboard, slice_start, slice_len).unwrap();
    // Compact proof for 2.5 KiB out of 64 KiB must be far smaller than the full blob.
    assert!(
        proof.len() < 8 * 1024,
        "expected compact slice proof, got {} bytes",
        proof.len()
    );

    let verified = verify_and_decode_slice(&proof, &ob.root, slice_start, slice_len).unwrap();
    assert_eq!(
        verified,
        data[slice_start as usize..(slice_start + slice_len) as usize]
    );

    // Flip one byte in leaf payload -> must fail with HashMismatch.
    let mut tampered = proof.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert_eq!(
        verify_and_decode_slice(&tampered, &ob.root, slice_start, slice_len),
        Err(BaoError::HashMismatch)
    );

    // Flip one byte in a parent hash -> must fail with HashMismatch.
    let mut bad_parent = proof.clone();
    bad_parent[12] ^= 0x80;
    assert_eq!(
        verify_and_decode_slice(&bad_parent, &ob.root, slice_start, slice_len),
        Err(BaoError::HashMismatch)
    );
}

#[test]
fn mmr_append_peaks_and_o_log_n_inclusion_proofs() {
    let mut mmr = Mmr::new();
    let mut leaves = Vec::new();
    for i in 0u64..100 {
        let d = BlobDigest::of(&i.to_le_bytes());
        mmr.append(d);
        leaves.push(d);
        let root = mmr.root();
        // Verify newest leaf and oldest leaf at every size.
        let p_new = mmr.inclusion_proof(i).unwrap();
        assert!(p_new.siblings.len() <= 7);
        assert!(p_new.peaks.len() <= 7);
        assert!(verify_inclusion_proof(&p_new, d, root));

        let p_first = mmr.inclusion_proof(0).unwrap();
        assert!(verify_inclusion_proof(&p_first, leaves[0], root));

        // Tampered leaf digest must fail.
        let mut wrong = d;
        wrong.0[0] ^= 0xFF;
        assert!(!verify_inclusion_proof(&p_new, wrong, root));
    }
}

#[test]
fn jcs_canonicalization_and_observation_mmr_wiring() {
    let a = r#"{ "z": 1, "a": [true, false, null, {"d": "x", "b": 2}] }"#;
    let b = r#"{"a":[true,false,null,{"b":2,"d":"x"}],"z":1}"#;
    assert_eq!(canonicalize_json(a).unwrap(), b);

    let ch = ChangeId::parse("kmpzsqxw").unwrap();
    let cm = CommitId::parse("aaaa1111bbbb2222cccc3333dddd4444").unwrap();
    let op = OpId::parse("1111222233334444").unwrap();
    let mk_draft = |meta: &str| ObservationDraft {
        observation_id: "OBS-JCS-1".into(),
        kind: ObservationKind::TestReceipt,
        change_id: ch.clone(),
        commit_id: cm.clone(),
        op_id: op.clone(),
        producer: "verifier".into(),
        passed: Some(true),
        summary: "jcs check".into(),
        payload_digest: BlobDigest::of(b"ok"),
        custody_uri: None,
        metadata_json: meta.into(),
        recorded_at_ms: 42,
    };
    let h1 = compute_observation_hash(0, BlobDigest::default(), &mk_draft(a));
    let h2 = compute_observation_hash(0, BlobDigest::default(), &mk_draft(b));
    assert_eq!(h1, h2, "JCS key order must yield identical record_hash");

    let mut chain = Vec::new();
    let r0 = append_observation_in_memory(&mut chain, mk_draft(a)).unwrap();
    verify_observation_chain(&chain).unwrap();
    let mmr = observation_chain_mmr(&chain);
    assert_eq!(r0.mmr_root, mmr.root());
    let proof = mmr.inclusion_proof(0).unwrap();
    assert!(verify_inclusion_proof(&proof, r0.record_hash, r0.mmr_root));

    let mut bad_mmr = chain.clone();
    bad_mmr[0].mmr_root.0[0] ^= 1;
    assert_eq!(
        verify_observation_chain(&bad_mmr),
        Err(ChainError::MmrRootMismatch { seq: 0 })
    );
}

#[test]
fn ltx1_wire_format_round_trip_and_corruption_detection() {
    assert_ne!(crc64_iso(b"123456789"), 0);
    assert_ne!(crc64_iso(b"123456789"), crc64_iso(b"123456780"));

    let page_size = 4096u32;
    let raw_db = prng_bytes((page_size as usize) * 5, 0x17A1);
    let (encoded, hdr, trailer) =
        encode_snapshot_ltx(&raw_db, page_size, 7, 1_700_000_000).unwrap();
    assert!(encoded.starts_with(LTX_MAGIC));
    assert!(encoded.len() > LTX_HEADER_SIZE + 16);
    assert_eq!(hdr.commit, 5);
    assert_eq!(hdr.min_txid, 1);
    assert_eq!(hdr.max_txid, 7);

    let decoded = decode_ltx(&encoded).unwrap();
    assert_eq!(decoded.header, hdr);
    assert_eq!(decoded.trailer, trailer);
    assert_eq!(reconstruct_db_from_ltx(&decoded).unwrap(), raw_db);

    // Flip a byte inside page payload -> caught by file CRC-64.
    let mut bad_body = encoded.clone();
    bad_body[LTX_HEADER_SIZE + 20] ^= 0x40;
    assert_eq!(decode_ltx(&bad_body), Err(LtxError::FileChecksumMismatch));

    // Flip header magic -> InvalidMagic.
    let mut bad_magic = encoded.clone();
    bad_magic[0] = b'X';
    assert_eq!(decode_ltx(&bad_magic), Err(LtxError::InvalidMagic));
}

#[test]
fn grnb0002_directory_header_parse_and_single_frame_range_unpack() {
    let mut acc = BundleAccumulator::new(4 * 1024 * 1024);
    let mut payloads = Vec::new();
    for i in 0u8..32 {
        let blob = prng_bytes(32 * 1024, u64::from(i) + 1);
        let h = acc.push(blob.clone());
        assert!(acc.contains(&h));
        payloads.push((h, blob));
    }
    let sealed = acc.seal().unwrap().unwrap();

    // Short prefix reports exact required directory bytes.
    assert!(matches!(
        parse_frame_directory_header(&sealed.compressed_bytes[..16]),
        Err(BundleError::TruncatedDirectory { required_bytes }) if required_bytes > 16
    ));

    let dir = parse_frame_directory_header(&sealed.compressed_bytes[..4096]).unwrap();
    let target_idx = 17;
    let entry = &sealed.entries[target_idx];
    let (frame, local_off) = dir
        .find_frame_for_slice(entry.byte_offset, entry.byte_len)
        .unwrap();
    let start = frame.comp_offset as usize;
    let end = start + frame.comp_len as usize;
    let unpacked = unpack_blob_from_frame(
        &sealed.compressed_bytes[start..end],
        &frame,
        local_off,
        entry.byte_len,
        &entry.blake3_hash,
    )
    .unwrap();
    assert_eq!(unpacked, payloads[target_idx].1);
}
