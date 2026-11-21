//! Local BLAKE3 CAS and port-backed (`CatalogStore` + `ObjectBackend`) drivers for `HephaestusBackend`.

use hephaestus_core::{
    BlobDigest, BundleAccumulator, BundleError, INLINE_BLOB_THRESHOLD,
    parse_frame_directory_header, unpack_blob_from_bundle, unpack_blob_from_frame,
};
use hephaestus_store::{BlobLocation, CatalogStore, ObjectBackend};
use jj_lib::backend::{BackendError, BackendResult};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DIR_PROBE_BYTES: u64 = 4096;

pub(crate) fn other_err(msg: impl Into<String>) -> BackendError {
    BackendError::Other(msg.into().into())
}

pub(crate) enum CasDriver {
    LocalDir(PathBuf),
    Ports {
        catalog: Arc<dyn CatalogStore>,
        objects: Arc<dyn ObjectBackend>,
    },
}

impl fmt::Debug for CasDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalDir(p) => f.debug_tuple("LocalDir").field(p).finish(),
            Self::Ports { objects, .. } => f
                .debug_struct("Ports")
                .field("object_backend", &objects.backend_kind())
                .finish(),
        }
    }
}

impl CasDriver {
    pub(crate) async fn put(&self, data: &[u8]) -> BackendResult<BlobDigest> {
        let digest = BlobDigest::of(data);
        match self {
            Self::LocalDir(dir) => write_local_cas(dir, &digest, data)?,
            Self::Ports { catalog, objects } => {
                if data.len() <= INLINE_BLOB_THRESHOLD {
                    catalog
                        .put_inline(&digest, data)
                        .await
                        .map_err(|e| other_err(e.to_string()))?;
                } else if !catalog
                    .contains_blob(&digest)
                    .await
                    .map_err(|e| other_err(e.to_string()))?
                {
                    let mut acc = BundleAccumulator::new(data.len().max(1024));
                    acc.push_prehashed(digest.0, data.to_vec());
                    if let Some(mut bundle) = acc.seal().map_err(|e| other_err(e.to_string()))? {
                        let bytes = std::mem::take(&mut bundle.compressed_bytes);
                        let obj_ref = objects
                            .put_bundle(&bundle.bundle_id, bytes)
                            .await
                            .map_err(|e| other_err(e.to_string()))?;
                        catalog
                            .record_bundle(&bundle, &obj_ref.object_id)
                            .await
                            .map_err(|e| other_err(e.to_string()))?;
                    }
                }
            }
        }
        Ok(digest)
    }

    pub(crate) async fn get(&self, digest: &BlobDigest) -> BackendResult<Option<Vec<u8>>> {
        let bytes = match self {
            Self::LocalDir(dir) => read_local_cas(dir, digest)?,
            Self::Ports { catalog, objects } => {
                match catalog
                    .lookup_blob(digest)
                    .await
                    .map_err(|e| other_err(e.to_string()))?
                {
                    None => None,
                    Some(BlobLocation::Inline(b)) => Some(b),
                    Some(BlobLocation::Packed {
                        object_id,
                        byte_offset,
                        byte_len,
                        ..
                    }) => Some(
                        fetch_packed_from_ports(
                            objects.as_ref(),
                            &object_id,
                            digest,
                            byte_offset,
                            byte_len,
                        )
                        .await?,
                    ),
                }
            }
        };
        if let Some(raw) = &bytes
            && BlobDigest::of(raw) != *digest
        {
            return Err(other_err(format!(
                "CAS BLAKE3 integrity mismatch for {digest}"
            )));
        }
        Ok(bytes)
    }
}

fn cas_blob_path(dir: &Path, digest: &BlobDigest) -> PathBuf {
    let hex = digest.to_hex();
    dir.join(&hex[..2]).join(hex)
}

pub(crate) fn write_local_cas(dir: &Path, digest: &BlobDigest, data: &[u8]) -> BackendResult<()> {
    let target = cas_blob_path(dir, digest);
    if target.exists() {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| other_err(format!("cas mkdir: {e}")))?;
    }
    let tmp = target.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, data).map_err(|e| other_err(format!("cas write: {e}")))?;
    std::fs::rename(&tmp, &target).map_err(|e| other_err(format!("cas rename: {e}")))?;
    Ok(())
}

fn read_local_cas(dir: &Path, digest: &BlobDigest) -> BackendResult<Option<Vec<u8>>> {
    match std::fs::read(cas_blob_path(dir, digest)) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(other_err(format!("cas read: {e}"))),
    }
}

async fn fetch_packed_from_ports(
    objects: &dyn ObjectBackend,
    object_id: &str,
    digest: &BlobDigest,
    byte_offset: u64,
    byte_len: u32,
) -> BackendResult<Vec<u8>> {
    let probe = objects
        .get_range(object_id, 0..DIR_PROBE_BYTES)
        .await
        .map_err(|e| other_err(e.to_string()))?;
    let (dir, prefix) = match parse_frame_directory_header(&probe) {
        Ok(d) => (d, probe),
        Err(BundleError::TruncatedDirectory { required_bytes }) => {
            let full = objects
                .get_range(object_id, 0..required_bytes as u64)
                .await
                .map_err(|e| other_err(e.to_string()))?;
            let d = parse_frame_directory_header(&full).map_err(|e| other_err(e.to_string()))?;
            (d, full)
        }
        Err(_) => {
            let full = objects
                .get_bundle(object_id)
                .await
                .map_err(|e| other_err(e.to_string()))?;
            return unpack_blob_from_bundle(&full, digest.as_bytes(), byte_offset, byte_len)
                .map_err(|e| other_err(e.to_string()));
        }
    };
    let (frame, local_off) = dir
        .find_frame_for_slice(byte_offset, byte_len)
        .map_err(|e| other_err(e.to_string()))?;
    let comp_end = frame.comp_offset + u64::from(frame.comp_len);
    let frame_bytes = if comp_end <= prefix.len() as u64 {
        prefix.slice(frame.comp_offset as usize..comp_end as usize)
    } else {
        objects
            .get_range(object_id, frame.comp_offset..comp_end)
            .await
            .map_err(|e| other_err(e.to_string()))?
    };
    unpack_blob_from_frame(&frame_bytes, &frame, local_off, byte_len, digest.as_bytes())
        .map_err(|e| other_err(e.to_string()))
}
