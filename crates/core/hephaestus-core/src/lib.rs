#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

//! Pure Sans-I/O core for Hephaestus.
//!
//! This crate has no filesystem, network, randomness, or wall-clock dependencies;
//! all time is injected deterministically via [`MonoTime`].

extern crate alloc;

pub mod bao;
mod bao_slice;
pub mod bundler;
mod bundler_frames;
pub mod cas;
pub mod cdc;
pub mod chain_verify;
mod crc64;
pub mod decision_log;
pub mod ids;
pub mod jcs;
pub mod ltx_format;
pub mod mmr;
pub mod oauth;
pub mod observation_log;
pub mod quota;
pub mod time;

pub use bao::{
    BAO_CHUNK_LEN, BAO_HEADER_LEN, BAO_PARENT_LEN, BaoError, BaoOutboard, bao_root_hash,
    decode_inboard, encode_inboard, encode_outboard, extract_slice_from_outboard,
    verify_and_decode_slice,
};
pub use bundler::{
    BUNDLE_MAGIC_V1, BUNDLE_MAGIC_V2, BundleAccumulator, BundleDirectoryHeader, BundleEntry,
    BundleError, BundleFrameDesc, INLINE_BLOB_THRESHOLD, MAX_BUNDLE_DIR_BYTES, MAX_BUNDLE_FRAMES,
    MAX_FRAME_COMP_BYTES, MAX_FRAME_RAW_BYTES, MAX_FRAME_RAW_DECODED_BYTES,
    MAX_LEGACY_V1_DECODED_BYTES, SealedBundle, TARGET_BUNDLE_MAX_BYTES, TARGET_BUNDLE_MIN_BYTES,
    bundle_frame_count, parse_frame_directory_header, unpack_blob_from_bundle,
    unpack_blob_from_frame,
};
pub use cas::{
    BlobDigest, BlobTier, IdempotencyKey, StreamKind, decode_hex, encode_hex, hash_bytes,
};
pub use cdc::{
    CdcChunk, FASTCDC_AVG_CHUNK, FASTCDC_MASK_L, FASTCDC_MASK_S, FASTCDC_MAX_CHUNK,
    FASTCDC_MIN_CHUNK, FastCdcConfig, GEAR_TABLE, chunk_bytes, chunk_bytes_with_config,
    next_chunk_len,
};
pub use chain_verify::{
    DEFAULT_LOG_PAGE_LIMIT, DecisionChainVerifier, MAX_LOG_PAGE_LIMIT, ObservationChainVerifier,
};
pub use decision_log::{
    ChainError, DecisionDraft, DecisionRecord, DecisionStatus, GENESIS_HASH,
    append_decision_in_memory, compute_decision_hash, decision_chain_mmr, verify_decision_chain,
};
pub use ids::{ChangeId, CommitId, IdError, OpId, RepoId};
pub use jcs::{JcsError, canonicalize_json};
pub use ltx_format::{
    LTX_CHECKSUM_FLAG, LTX_HEADER_SIZE, LTX_MAGIC, LTX_TRAILER_SIZE, LtxDocument, LtxError,
    LtxHeader, LtxPageFrame, LtxTrailer, compute_db_checksum, crc64_iso, crc64_iso_update,
    decode_ltx, encode_ltx, encode_snapshot_ltx, ltx_page_checksum, reconstruct_db_from_ltx,
};
pub use mmr::{
    Mmr, MmrAppendOutput, MmrError, MmrProof, MmrProofPlan, MmrSibling, bag_mmr_peaks,
    compute_append_nodes, hash_mmr_leaf, hash_mmr_node, leaf_count_to_mmr_size, leaf_index_to_pos,
    peak_positions, proof_node_positions, verify_inclusion_proof,
};
pub use oauth::{
    DRIVE_FILE_SCOPE, DriveOAuthError, DriveOAuthFsm, GOOGLE_AUTH_ENDPOINT, GOOGLE_TOKEN_ENDPOINT,
    PkcePair, SecretString, TokenFormRequest, TokenLease,
};
pub use observation_log::{
    ObservationDraft, ObservationFilter, ObservationKind, ObservationRecord,
    append_observation_in_memory, compute_observation_hash, matches_observation_filter,
    observation_chain_mmr, verify_observation_chain,
};
pub use quota::{
    DAILY_TRANSFER_CAP_BYTES, DriveOpKind, DriveQuotaGovernor, MAX_UNITS_PER_MINUTE, QuotaDecision,
    WRITE_BURST_CAPACITY, WRITE_REFILL_PER_SEC,
};
pub use time::MonoTime;
