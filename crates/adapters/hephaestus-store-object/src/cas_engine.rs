//! Content-addressed inline/packed CAS engine composing `CatalogStore`, `ObjectBackend`, and `BundleAccumulator`.

use bytes::Bytes;
use hephaestus_core::{
    BUNDLE_MAGIC_V2, BlobDigest, BundleAccumulator, BundleError, MAX_BUNDLE_DIR_BYTES,
    MAX_FRAME_COMP_BYTES, MAX_FRAME_RAW_DECODED_BYTES, MAX_LEGACY_V1_DECODED_BYTES,
    parse_frame_directory_header, unpack_blob_from_bundle, unpack_blob_from_frame,
};
use hephaestus_store::{BlobLocation, CatalogStats, CatalogStore, ObjectBackend, StoreError};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Initial prefix probe size (4 KiB) sufficient to cover the `GRNB0002` frame directory
/// for bundles up to ~32 MiB (`12 + 130 * 24 = 3,132` bytes).
const INITIAL_DIR_PROBE_BYTES: u64 = 4096;

/// Content-addressed storage coordinator tiering `<= 8 KiB` blobs inline in SQLite WAL
/// and coalescing larger blobs into `GRNB0002` framed Zstd bundles on [`ObjectBackend`].
pub struct PackedCasEngine {
    catalog: Arc<dyn CatalogStore>,
    objects: Arc<dyn ObjectBackend>,
    accumulator: Mutex<BundleAccumulator>,
}

impl PackedCasEngine {
    /// Creates a [`PackedCasEngine`] targeting `target_bundle_bytes` per `GRNB0002` bundle.
    #[must_use]
    pub fn new(
        catalog: Arc<dyn CatalogStore>,
        objects: Arc<dyn ObjectBackend>,
        target_bundle_bytes: usize,
    ) -> Self {
        Self {
            catalog,
            objects,
            accumulator: Mutex::new(BundleAccumulator::new(target_bundle_bytes)),
        }
    }

    /// Returns a reference to the backing [`CatalogStore`].
    #[must_use]
    pub fn catalog(&self) -> &Arc<dyn CatalogStore> {
        &self.catalog
    }

    /// Returns a reference to the backing [`ObjectBackend`].
    #[must_use]
    pub fn object_backend(&self) -> &Arc<dyn ObjectBackend> {
        &self.objects
    }

    /// Stores `data` with BLAKE3 deduplication. Blobs `<= 8 KiB` (unless `force_pack`) are
    /// persisted inline; larger blobs stage into `BundleAccumulator` and flush at target size.
    pub async fn put_blob(
        &self,
        data: Vec<u8>,
        force_pack: bool,
    ) -> Result<BlobDigest, StoreError> {
        let digest = BlobDigest::of(&data);
        if !force_pack && BundleAccumulator::should_inline(&data) {
            self.catalog.put_inline(&digest, &data).await?;
            return Ok(digest);
        }
        if self.catalog.contains_blob(&digest).await? {
            return Ok(digest);
        }

        let should_flush = {
            let mut acc = self.accumulator.lock().await;
            acc.push_prehashed(digest.0, data);
            acc.ready_to_seal()
        };
        if should_flush {
            let _ = self.flush_bundle().await?;
        }
        Ok(digest)
    }

    /// Seals all staged blobs into one `GRNB0002` bundle, uploads it to [`ObjectBackend`]
    /// without cloning its compressed buffer, and commits packed index rows to [`CatalogStore`].
    pub async fn flush_bundle(&self) -> Result<Option<String>, StoreError> {
        let sealed = { self.accumulator.lock().await.seal()? };
        let Some(mut bundle) = sealed else {
            return Ok(None);
        };
        let payload = Bytes::from(std::mem::take(&mut bundle.compressed_bytes));
        let obj_ref = self
            .objects
            .put_bundle(&bundle.bundle_id, payload.into())
            .await?;
        self.catalog
            .record_bundle(&bundle, &obj_ref.object_id)
            .await?;
        let _ = self.catalog.checkpoint_wal().await;
        Ok(Some(obj_ref.object_id))
    }

    /// Retrieves a blob by BLAKE3 digest from staging memory, inline SQLite, or a bounded
    /// `GRNB0002` range read (fetching only directory header + target Zstd frame).
    pub async fn get_blob(&self, digest: &BlobDigest) -> Result<Option<Vec<u8>>, StoreError> {
        if let Some(staged) = self.accumulator.lock().await.peek_blob(digest.as_bytes()) {
            return Ok(Some(staged));
        }
        let loc = self.catalog.lookup_blob(digest).await?;
        match loc {
            None => Ok(None),
            Some(BlobLocation::Inline(bytes)) => Ok(Some(bytes)),
            Some(BlobLocation::Packed {
                object_id,
                byte_offset,
                byte_len,
                ..
            }) => {
                let blob = self
                    .fetch_packed_blob(&object_id, digest, byte_offset, byte_len)
                    .await?;
                Ok(Some(blob))
            }
        }
    }

    async fn fetch_packed_blob(
        &self,
        object_id: &str,
        digest: &BlobDigest,
        byte_offset: u64,
        byte_len: u32,
    ) -> Result<Vec<u8>, StoreError> {
        let probe = self
            .objects
            .get_range(object_id, 0..INITIAL_DIR_PROBE_BYTES)
            .await?;

        let (dir, prefix) = match parse_frame_directory_header(&probe) {
            Ok(dir) => (dir, probe),
            Err(BundleError::TruncatedDirectory { required_bytes }) => {
                if required_bytes > MAX_BUNDLE_DIR_BYTES {
                    return Err(StoreError::Bundle(BundleError::InvalidFormat));
                }
                let full_dir = self
                    .objects
                    .get_range(object_id, 0..required_bytes as u64)
                    .await?;
                let dir = parse_frame_directory_header(&full_dir)?;
                (dir, full_dir)
            }
            Err(BundleError::InvalidFormat) => {
                if probe.starts_with(BUNDLE_MAGIC_V2) {
                    return Err(StoreError::Bundle(BundleError::InvalidFormat));
                }
                // Legacy GRNB0001 single-stream fallback with strict size ceiling.
                let max_legacy_comp =
                    (MAX_LEGACY_V1_DECODED_BYTES as u64).saturating_add(64 * 1024);
                if let Some(meta) = self.objects.head_bundle(object_id).await?
                    && meta.size_bytes > max_legacy_comp
                {
                    return Err(StoreError::Bundle(BundleError::InvalidFormat));
                }
                let compressed = self.objects.get_bundle(object_id).await?;
                if compressed.len() as u64 > max_legacy_comp {
                    return Err(StoreError::Bundle(BundleError::InvalidFormat));
                }
                return Ok(unpack_blob_from_bundle(
                    &compressed,
                    digest.as_bytes(),
                    byte_offset,
                    byte_len,
                )?);
            }
            Err(err) => return Err(StoreError::Bundle(err)),
        };

        let (frame, local_off) = dir.find_frame_for_slice(byte_offset, byte_len)?;
        if frame.comp_len as usize > MAX_FRAME_COMP_BYTES
            || frame.raw_len as usize > MAX_FRAME_RAW_DECODED_BYTES
        {
            return Err(StoreError::Bundle(BundleError::InvalidFormat));
        }
        let comp_start = frame.comp_offset;
        let comp_end = comp_start
            .checked_add(u64::from(frame.comp_len))
            .ok_or(StoreError::Bundle(BundleError::InvalidFormat))?;

        let frame_bytes = if comp_end <= prefix.len() as u64 {
            prefix.slice(comp_start as usize..comp_end as usize)
        } else {
            self.objects
                .get_range(object_id, comp_start..comp_end)
                .await?
        };
        Ok(unpack_blob_from_frame(
            &frame_bytes,
            &frame,
            local_off,
            byte_len,
            digest.as_bytes(),
        )?)
    }

    /// Returns total uncompressed bytes currently staged in memory.
    pub async fn pending_bytes(&self) -> usize {
        self.accumulator.lock().await.pending_bytes()
    }

    /// Returns catalog statistics combined with current staged bytes.
    pub async fn stats(&self) -> Result<(CatalogStats, usize), StoreError> {
        let s = self.catalog.stats().await?;
        let pending = self.pending_bytes().await;
        Ok((s, pending))
    }
}
