#![forbid(unsafe_code)]
//! Deterministic simulation tests for `hephaestus-core` (10k-blob GRNB0002, quota, OAuth, and hash chains).

use hephaestus_core::{
    BUNDLE_MAGIC_V1, BUNDLE_MAGIC_V2, BlobDigest, BundleAccumulator, BundleError, ChainError,
    ChangeId, CommitId, DRIVE_FILE_SCOPE, DecisionDraft, DecisionStatus, DriveOAuthError,
    DriveOAuthFsm, DriveOpKind, DriveQuotaGovernor, GENESIS_HASH, MAX_FRAME_RAW_BYTES, MonoTime,
    ObservationDraft, ObservationFilter, ObservationKind, OpId, PkcePair, QuotaDecision,
    SecretString, append_decision_in_memory, append_observation_in_memory, bundle_frame_count,
    matches_observation_filter, unpack_blob_from_bundle, verify_decision_chain,
    verify_observation_chain,
};

#[test]
fn dst_10k_blobs_grnb0002_zstd_interop_and_grnb0001_compat() {
    // 1. Pack 10,000 distinct blobs into one GRNB0002 bundle.
    let mut acc = BundleAccumulator::new(8 * 1024 * 1024);
    let mut samples = Vec::new();
    for i in 0u32..10_000 {
        let payload = format!("dst-blob-{i:05}-content-{}", i.wrapping_mul(31)).into_bytes();
        let hash = acc.push(payload.clone());
        if matches!(i, 0 | 1 | 42 | 2047 | 5000 | 9999) {
            samples.push((i as usize, hash, payload));
        }
    }
    assert_eq!(acc.pending_count(), 10_000);
    let sealed = acc.seal().unwrap().expect("one 10k-blob sealed bundle");
    assert_eq!(sealed.entries.len(), 10_000);
    assert!(sealed.compressed_bytes.starts_with(BUNDLE_MAGIC_V2));
    assert!(bundle_frame_count(&sealed.compressed_bytes).unwrap() >= 2);

    // Every sample unpacks cleanly via pure no_std ruzstd decoder and verifies BLAKE3.
    for (idx, hash, expected) in &samples {
        let entry = &sealed.entries[*idx];
        assert_eq!(&entry.blake3_hash, hash);
        let got = unpack_blob_from_bundle(
            &sealed.compressed_bytes,
            hash,
            entry.byte_offset,
            entry.byte_len,
        )
        .unwrap();
        assert_eq!(&got, expected);
    }

    // 2. Cross-verify that standard C libzstd (`zstd::stream::decode_all`) can decode frames
    //    written by hephaestus-core's pure no_std ruzstd encoder.
    let mut big_acc = BundleAccumulator::new(4 * 1024 * 1024);
    let mut big_blobs = Vec::new();
    for i in 0usize..256 {
        let mut data = vec![0u8; 16 * 1024];
        for (j, b) in data.iter_mut().enumerate() {
            *b = ((i.wrapping_mul(31) ^ j.wrapping_mul(17)) & 0xFF) as u8;
        }
        let h = big_acc.push(data.clone());
        big_blobs.push((h, data));
    }
    assert!(big_acc.ready_to_seal());
    let big_sealed = big_acc.seal().unwrap().unwrap();
    assert_eq!(bundle_frame_count(&big_sealed.compressed_bytes), Some(17));

    // Read one compressed frame directly using C libzstd from the GRNB0002 directory.
    let frame1_comp_off = u64::from_le_bytes(
        big_sealed.compressed_bytes[12 + 24 + 12..12 + 24 + 20]
            .try_into()
            .unwrap(),
    ) as usize;
    let frame1_comp_len = u32::from_le_bytes(
        big_sealed.compressed_bytes[12 + 24 + 20..12 + 24 + 24]
            .try_into()
            .unwrap(),
    ) as usize;
    let libzstd_decoded = zstd::stream::decode_all(
        &big_sealed.compressed_bytes[frame1_comp_off..frame1_comp_off + frame1_comp_len],
    )
    .unwrap();
    assert_eq!(libzstd_decoded.len(), 256 * 1024);

    // 3. Corrupt hash and OOB slice rejection + oversized > 256 KiB blob isolation.
    let mut bad_hash = big_sealed.entries[0].blake3_hash;
    bad_hash[0] ^= 0xFF;
    assert_eq!(
        unpack_blob_from_bundle(
            &big_sealed.compressed_bytes,
            &bad_hash,
            big_sealed.entries[0].byte_offset,
            big_sealed.entries[0].byte_len,
        ),
        Err(BundleError::ChecksumMismatch)
    );
    assert!(matches!(
        unpack_blob_from_bundle(
            &big_sealed.compressed_bytes,
            &big_sealed.entries[0].blake3_hash,
            big_sealed.raw_bytes_len as u64,
            16,
        ),
        Err(BundleError::SliceOutOfBounds { .. })
    ));

    let mut over_acc = BundleAccumulator::new(1024);
    let over_blob = vec![0x5Au8; MAX_FRAME_RAW_BYTES + 4096];
    let over_hash = over_acc.push(over_blob.clone());
    let over_sealed = over_acc.seal().unwrap().unwrap();
    assert_eq!(bundle_frame_count(&over_sealed.compressed_bytes), Some(2));
    assert_eq!(
        unpack_blob_from_bundle(
            &over_sealed.compressed_bytes,
            &over_hash,
            over_sealed.entries[0].byte_offset,
            over_sealed.entries[0].byte_len,
        )
        .unwrap(),
        over_blob
    );

    // 4. Legacy GRNB0001 compressed with C libzstd level 3 still decodes via no_std core.
    let legacy = b"legacy-grnb0001-payload-verified".to_vec();
    let legacy_hash = *blake3::hash(&legacy).as_bytes();
    let hdr_len = 12 + 44;
    let mut raw_v1 = Vec::with_capacity(hdr_len + legacy.len());
    raw_v1.extend_from_slice(BUNDLE_MAGIC_V1);
    raw_v1.extend_from_slice(&1u32.to_le_bytes());
    raw_v1.extend_from_slice(&legacy_hash);
    raw_v1.extend_from_slice(&(hdr_len as u64).to_le_bytes());
    raw_v1.extend_from_slice(&(legacy.len() as u32).to_le_bytes());
    raw_v1.extend_from_slice(&legacy);
    let comp_v1 = zstd::bulk::compress(&raw_v1, 3).unwrap();
    assert_eq!(bundle_frame_count(&comp_v1), None);
    assert_eq!(
        unpack_blob_from_bundle(&comp_v1, &legacy_hash, hdr_len as u64, legacy.len() as u32)
            .unwrap(),
        legacy
    );
}

#[test]
fn quota_governor_and_oauth_pkce_fsm_invariants() {
    let mut gov = DriveQuotaGovernor::new(MonoTime(0), 77);
    for _ in 0..30 {
        assert_eq!(
            gov.check_and_consume(DriveOpKind::FilesCreate, 4096, MonoTime(0)),
            QuotaDecision::Allow
        );
    }
    assert!(matches!(
        gov.check_and_consume(DriveOpKind::FilesCreate, 4096, MonoTime(0)),
        QuotaDecision::WaitUntil(_)
    ));
    let wake = gov.on_rate_limited(MonoTime(1_000), None);
    assert!(wake.0 >= 1_500);
    assert_eq!(
        gov.check_and_consume(DriveOpKind::FilesGet, 0, MonoTime(1_100)),
        QuotaDecision::WaitUntil(wake)
    );

    let bad = DriveOAuthFsm::new(
        "cid",
        "http://[::1]:8765/cb",
        "https://www.googleapis.com/auth/drive",
    );
    assert!(matches!(bad, Err(DriveOAuthError::ForbiddenScope(_))));

    let mut fsm = DriveOAuthFsm::new("cid-123", "http://[::1]:8765/cb", DRIVE_FILE_SCOPE).unwrap();
    let pkce = PkcePair::from_entropy([0x42; 32], [0x77; 16]);
    let state = pkce.state.clone();
    let url = fsm.begin_consent(pkce);
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("drive.file"));

    let req = fsm.handle_callback(&state, "auth-code-xyz").unwrap();
    assert_eq!(req.endpoint, "https://oauth2.googleapis.com/token");
    let secret = SecretString::new("ya29.super-secret-token");
    assert!(!format!("{secret:?}").contains("super-secret"));
    assert!(!format!("{secret}").contains("super-secret"));

    fsm.apply_token_response(
        secret,
        Some(SecretString::new("1//refresh")),
        3600,
        MonoTime(0),
    );
    assert!(fsm.valid_access_token(MonoTime(1_000)).is_some());
    assert!(fsm.valid_access_token(MonoTime(3_590_000)).is_none());
    assert!(fsm.build_refresh_request().is_ok());
}

#[test]
fn decision_and_observation_hash_chains_enforce_tamper_and_orthogonality_invariants() {
    let ch1 = ChangeId::parse("kmpzsqxw").unwrap();
    let ch2 = ChangeId::parse("lytvxmpz").unwrap();
    let cm1 = CommitId::parse("aaaa1111bbbb2222cccc3333dddd4444").unwrap();
    let op1 = OpId::parse("1111222233334444").unwrap();
    let op2 = OpId::parse("5555666677778888").unwrap();

    let mut decisions = Vec::new();
    let d0 = append_decision_in_memory(
        &mut decisions,
        DecisionDraft {
            decision_id: "DEC-0001".into(),
            change_id: ch1.clone(),
            op_id: op1.clone(),
            author: "architect".into(),
            status: DecisionStatus::Proposed,
            rationale: "Use GRNB0002 framed Zstd bundles".into(),
            alternatives: vec!["GRNB0001 single stream".into()],
            supersedes: None,
            recorded_at_ms: 100,
        },
    )
    .unwrap();
    assert_eq!(d0.seq, 0);
    assert_eq!(d0.prev_hash, GENESIS_HASH);

    let d1 = append_decision_in_memory(
        &mut decisions,
        DecisionDraft {
            decision_id: "DEC-0002".into(),
            change_id: ch1.clone(),
            op_id: op2.clone(),
            author: "reviewer".into(),
            status: DecisionStatus::Accepted,
            rationale: "Confirmed 256 KiB random-access frames".into(),
            alternatives: vec![],
            supersedes: Some("DEC-0001".into()),
            recorded_at_ms: 200,
        },
    )
    .unwrap();
    assert_eq!(d1.prev_hash, d0.record_hash);
    verify_decision_chain(&decisions).unwrap();

    // Tampering with rationale breaks verification at seq 0.
    let mut tampered = decisions.clone();
    tampered[0].rationale = "Silently altered rationale".into();
    assert_eq!(
        verify_decision_chain(&tampered),
        Err(ChainError::RecordHashMismatch { seq: 0 })
    );

    // Gap / non-monotonic seq fails.
    let mut gapped = decisions.clone();
    gapped[1].seq = 2;
    assert_eq!(
        verify_decision_chain(&gapped),
        Err(ChainError::NonMonotonicSeq {
            index: 1,
            expected: 1,
            actual: 2
        })
    );

    // Orthogonal observations accumulate without changing CommitId/ChangeId.
    let mut observations = Vec::new();
    let kinds = [
        ObservationKind::TestReceipt,
        ObservationKind::Benchmark,
        ObservationKind::VerifierVerdict,
        ObservationKind::O11yCustodyRef,
        ObservationKind::AgentTrace,
    ];
    for (idx, kind) in kinds.into_iter().enumerate() {
        append_observation_in_memory(
            &mut observations,
            ObservationDraft {
                observation_id: format!("OBS-{idx:04}"),
                kind,
                change_id: if idx % 2 == 0 {
                    ch1.clone()
                } else {
                    ch2.clone()
                },
                commit_id: cm1.clone(),
                op_id: op1.clone(),
                producer: "ci-runner".into(),
                passed: Some(true),
                summary: format!("Recorded {}", kind.as_str()),
                payload_digest: BlobDigest::of(format!("payload-{idx}").as_bytes()),
                custody_uri: Some(format!("https://o11y.example.invalid/trace/{idx}")),
                metadata_json: "{}".into(),
                recorded_at_ms: 1_000 + idx as u64,
            },
        )
        .unwrap();
    }
    verify_observation_chain(&observations).unwrap();
    let filter = ObservationFilter {
        change_id: Some(ch1),
        kind: Some(ObservationKind::VerifierVerdict),
        ..ObservationFilter::default()
    };
    let hits: Vec<_> = observations
        .iter()
        .filter(|r| matches_observation_filter(r, &filter))
        .collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].observation_id, "OBS-0002");

    // Tampering with observation metadata fails verification.
    let mut obs_tampered = observations.clone();
    obs_tampered[3].summary = "Forged summary".into();
    assert_eq!(
        verify_observation_chain(&obs_tampered),
        Err(ChainError::RecordHashMismatch { seq: 3 })
    );
}
