#![forbid(unsafe_code)]
//! Security regression tests for Daybreak findings #11, #12, #13, and #14 in `hephaestus-core`.

use hephaestus_core::{
    BUNDLE_MAGIC_V1, BUNDLE_MAGIC_V2, BlobDigest, BundleError, ChangeId, CommitId, JcsError,
    MAX_BUNDLE_FRAMES, MAX_FRAME_COMP_BYTES, MAX_FRAME_RAW_DECODED_BYTES,
    MAX_LEGACY_V1_DECODED_BYTES, ObservationDraft, OpId, RepoId, append_observation_in_memory,
    canonicalize_json, parse_frame_directory_header, unpack_blob_from_bundle,
};
use serde::Deserialize;
use serde::de::value::{Error as DeValueError, StrDeserializer};

#[test]
fn jcs_rejects_duplicate_keys_at_all_depths_and_unicode_escapes() {
    assert!(matches!(
        canonicalize_json(r#"{"a":1,"a":2}"#),
        Err(JcsError::DuplicateKey(ref k)) if k == "a"
    ));
    assert!(matches!(
        canonicalize_json(r#"{"outer":{"x":1,"y":2,"x":3}}"#),
        Err(JcsError::DuplicateKey(ref k)) if k == "x"
    ));
    assert!(matches!(
        canonicalize_json(r#"[{"k":1,"\u006b":2}]"#),
        Err(JcsError::DuplicateKey(ref k)) if k == "k"
    ));

    let ch = ChangeId::parse("kmpzsqxw").unwrap();
    let cm = CommitId::parse("aaaa1111bbbb2222cccc3333dddd4444").unwrap();
    let op = OpId::parse("1111222233334444").unwrap();
    let mut obs = Vec::new();
    let res = append_observation_in_memory(
        &mut obs,
        ObservationDraft {
            observation_id: "OBS-DUP".into(),
            kind: hephaestus_core::ObservationKind::TestReceipt,
            change_id: ch,
            commit_id: cm,
            op_id: op,
            producer: "tester".into(),
            passed: Some(false),
            summary: "duplicate key attempt".into(),
            payload_digest: BlobDigest::of(b"x"),
            custody_uri: None,
            metadata_json: r#"{"admin":false,"admin":true}"#.into(),
            recorded_at_ms: 1,
        },
    );
    assert!(res.is_err());
}

#[test]
fn grnb0002_directory_enforces_frame_and_size_ceilings() {
    // 1. Frame count above MAX_BUNDLE_FRAMES must fail before reading directory entries.
    let mut bad_count = Vec::from(*BUNDLE_MAGIC_V2);
    bad_count.extend_from_slice(&((MAX_BUNDLE_FRAMES as u32) + 1).to_le_bytes());
    bad_count.extend_from_slice(&[0u8; 64]);
    assert_eq!(
        parse_frame_directory_header(&bad_count),
        Err(BundleError::InvalidFormat)
    );

    // 2. Single frame raw_len or comp_len exceeding policy must fail in directory parse.
    let mut bad_frame = Vec::from(*BUNDLE_MAGIC_V2);
    bad_frame.extend_from_slice(&1u32.to_le_bytes());
    bad_frame.extend_from_slice(&0u64.to_le_bytes()); // raw_offset
    bad_frame.extend_from_slice(&((MAX_FRAME_RAW_DECODED_BYTES as u32) + 1).to_le_bytes());
    bad_frame.extend_from_slice(&36u64.to_le_bytes()); // comp_offset
    bad_frame.extend_from_slice(&16u32.to_le_bytes()); // comp_len
    assert_eq!(
        parse_frame_directory_header(&bad_frame),
        Err(BundleError::InvalidFormat)
    );

    let mut bad_comp = Vec::from(*BUNDLE_MAGIC_V2);
    bad_comp.extend_from_slice(&1u32.to_le_bytes());
    bad_comp.extend_from_slice(&0u64.to_le_bytes());
    bad_comp.extend_from_slice(&1024u32.to_le_bytes());
    bad_comp.extend_from_slice(&36u64.to_le_bytes());
    bad_comp.extend_from_slice(&((MAX_FRAME_COMP_BYTES as u32) + 1).to_le_bytes());
    assert_eq!(
        parse_frame_directory_header(&bad_comp),
        Err(BundleError::InvalidFormat)
    );
}

#[test]
fn legacy_grnb0001_rejects_oversized_zstd_decompression_bomb() {
    let mut raw_bomb = Vec::with_capacity(MAX_LEGACY_V1_DECODED_BYTES + 4096);
    raw_bomb.extend_from_slice(BUNDLE_MAGIC_V1);
    raw_bomb.resize(MAX_LEGACY_V1_DECODED_BYTES + 4096, 0);
    let compressed = zstd::bulk::compress(&raw_bomb, 3).unwrap();
    drop(raw_bomb);
    assert!(compressed.len() < 128 * 1024);

    let err = unpack_blob_from_bundle(&compressed, &[0u8; 32], 0, 16).unwrap_err();
    assert_eq!(err, BundleError::InvalidFormat);
}

#[test]
fn identifier_deserialization_enforces_constructor_invariants() {
    let long = "a".repeat(257);
    for bad in ["", "../escape", "a..b", "/lead", "trail/", "a b", &long] {
        assert!(
            RepoId::deserialize(StrDeserializer::<DeValueError>::new(bad)).is_err(),
            "{bad}"
        );
        assert!(
            ChangeId::deserialize(StrDeserializer::<DeValueError>::new(bad)).is_err(),
            "{bad}"
        );
        assert!(
            CommitId::deserialize(StrDeserializer::<DeValueError>::new(bad)).is_err(),
            "{bad}"
        );
        assert!(
            OpId::deserialize(StrDeserializer::<DeValueError>::new(bad)).is_err(),
            "{bad}"
        );
    }
    assert!(ChangeId::deserialize(StrDeserializer::<DeValueError>::new("org/ch")).is_err());
    assert!(CommitId::deserialize(StrDeserializer::<DeValueError>::new("org/cm")).is_err());
    assert!(OpId::deserialize(StrDeserializer::<DeValueError>::new("org/op")).is_err());

    let valid_repo = RepoId::deserialize(StrDeserializer::<DeValueError>::new("org/repo-1.v2"))
        .expect("valid repo id");
    assert_eq!(valid_repo.as_str(), "org/repo-1.v2");
}
