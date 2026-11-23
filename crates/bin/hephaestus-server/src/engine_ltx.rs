//! Content-addressed `"LTX1"` disaster-recovery snapshot shipping and digest/freshness-verified
//! restore for [`crate::HephaestusEngine`].

use crate::engine::HephaestusEngine;
use crate::quic_spki::ct_eq_32;
use hephaestus_core::BlobDigest;
use hephaestus_store::{CatalogStore as _, StoreError};
use hephaestus_store_sqlite::{SqliteStore, restore_ltx_snapshot_zstd_verified};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::Ordering;

/// Content-addressed receipt emitted when shipping a Zstd `"LTX1"` snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtxSnapshotReceipt {
    /// Object storage key or Drive `fileId` holding the uploaded `.ltx.zst` snapshot.
    pub object_id: String,
    /// Monotonic SQLite `snapshot_seq` (`txid`) captured in the LTX1 header.
    pub snapshot_seq: u64,
    /// Authoritative `max_txid` recorded in the LTX1 snapshot.
    pub txid: u64,
    /// BLAKE3 digest of the uncompressed SQLite database bytes.
    pub raw_digest: BlobDigest,
    /// BLAKE3 digest of the compressed `.ltx.zst` snapshot payload.
    pub snapshot_digest: BlobDigest,
}

impl HephaestusEngine {
    /// Exports a Zstd `"LTX1"` snapshot, ships it under a content-addressed object key,
    /// and returns its [`LtxSnapshotReceipt`] carrying BLAKE3 digests and monotonic `txid`.
    pub async fn ship_ltx_snapshot_manifest(&self) -> Result<LtxSnapshotReceipt, StoreError> {
        let payload = self.sqlite().export_ltx_snapshot_zstd().await?;
        let meta = self
            .sqlite()
            .latest_ltx_snapshot_meta()
            .await?
            .ok_or_else(|| StoreError::Backend("missing exported ltx_snapshots metadata".into()))?;
        let snapshot_digest = BlobDigest::of(&payload);
        let raw_prefix = &meta.raw_digest.to_hex()[..16];
        let key = format!("ltx/snapshot-{:08}-{raw_prefix}.ltx.zst", meta.snapshot_seq);
        let obj = self
            .cas()
            .object_backend()
            .put_bundle(&key, payload)
            .await?;
        Ok(LtxSnapshotReceipt {
            object_id: obj.object_id,
            snapshot_seq: meta.snapshot_seq,
            txid: meta.snapshot_seq,
            raw_digest: meta.raw_digest,
            snapshot_digest,
        })
    }

    /// Downloads an `"LTX1"` snapshot from [`hephaestus_store::ObjectBackend`] and performs
    /// verified DR restore requiring exact BLAKE3 digest(s) and monotonic `txid` freshness.
    pub async fn restore_ltx_snapshot_verified(
        &self,
        object_id: &str,
        dest_path: &Path,
        expected_raw_digest: &BlobDigest,
        expected_snapshot_digest: Option<&BlobDigest>,
        min_txid: Option<u64>,
    ) -> Result<SqliteStore, StoreError> {
        let bytes = self.cas().object_backend().get_bundle(object_id).await?;
        if let Some(exp_snap) = expected_snapshot_digest {
            let actual_snap = BlobDigest::of(&bytes);
            if !ct_eq_32(&actual_snap.0, &exp_snap.0) {
                return Err(StoreError::InvalidInput(
                    "LTX1 compressed snapshot BLAKE3 digest mismatch".into(),
                ));
            }
        }
        let prior_floor = self.last_restored_txid_floor();
        let effective_min = match (min_txid, prior_floor) {
            (Some(m), 0) => Some(m),
            (Some(m), prev) => Some(m.max(prev)),
            (None, 0) => None,
            (None, prev) => Some(prev),
        };
        let dest = dest_path.to_path_buf();
        let raw_digest = *expected_raw_digest;
        let restored = tokio::task::spawn_blocking(move || {
            restore_ltx_snapshot_zstd_verified(&bytes, &dest, &raw_digest, effective_min)
        })
        .await
        .map_err(|e| StoreError::Backend(format!("join restore_ltx_snapshot: {e}")))??;

        let restored_seq = restored
            .latest_ltx_snapshot_meta()
            .await?
            .map_or(0, |m| m.snapshot_seq)
            .max(effective_min.unwrap_or(0));
        if restored_seq > 0 {
            self.advance_restored_txid_floor(restored_seq);
        }
        Ok(restored)
    }

    pub(crate) fn last_restored_txid_floor(&self) -> u64 {
        self.last_restored_txid.load(Ordering::Acquire)
    }

    pub(crate) fn advance_restored_txid_floor(&self, txid: u64) {
        let _ = self.last_restored_txid.fetch_max(txid, Ordering::AcqRel);
    }
}
