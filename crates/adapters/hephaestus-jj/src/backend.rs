//! Native CAS-backed `jj_lib::backend::Backend` registered as `"hephaestus"`.
//!
//! Stores files via pure `#![no_std]` FastCDC (`8/32/128 KiB`) chunking + BLAKE3 manifests,
//! and stores trees, commits, and symlinks directly in BLAKE3 content-addressed storage.

use crate::cas_codec::{
    CasFileManifest, decode_commit, decode_tree, empty_tree_bytes_and_digest, encode_commit,
    encode_tree,
};
use crate::cas_driver::{CasDriver, other_err, write_local_cas};
use async_trait::async_trait;
use futures::io::Cursor;
use futures::stream::{self, BoxStream};
use futures::{AsyncRead, AsyncReadExt as _, StreamExt as _};
use hephaestus_core::{BlobDigest, chunk_bytes};
use hephaestus_store::{CatalogStore, ObjectBackend};
use jj_lib::backend::{
    Backend, BackendError, BackendResult, ChangeId, Commit, CommitId, CopyHistory, CopyId,
    CopyRecord, FileId, RelatedCopy, SecureSig, SigningFn, SymlinkId, Tree, TreeId,
    make_root_commit,
};
use jj_lib::default_backend_factories::default_backend_factories;
use jj_lib::object_id::ObjectId;
use jj_lib::repo::StoreFactories;
use jj_lib::repo_path::{RepoPath, RepoPathBuf};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

const COMMIT_ID_LENGTH: usize = 32;
const CHANGE_ID_LENGTH: usize = 16;

fn not_found_err(id: &impl ObjectId) -> BackendError {
    BackendError::ObjectNotFound {
        object_type: id.object_type(),
        hash: id.hex(),
        source: None,
    }
}

fn id_to_digest(id: &impl ObjectId) -> BackendResult<BlobDigest> {
    let arr: [u8; 32] = id
        .as_bytes()
        .try_into()
        .map_err(|_| other_err(format!("expected 32-byte BLAKE3 id, got {}", id.hex())))?;
    Ok(BlobDigest(arr))
}

/// Authoritative `jj-lib` storage backend backed by Hephaestus FastCDC + BLAKE3 CAS.
#[derive(Debug)]
pub struct HephaestusBackend {
    driver: CasDriver,
    root_commit_id: CommitId,
    root_change_id: ChangeId,
    empty_tree_id: TreeId,
    files_written: AtomicU64,
    chunks_written: AtomicU64,
    commits_written: AtomicU64,
}

impl HephaestusBackend {
    /// Backend type identifier persisted in `.jj/repo/store/type`.
    pub const NAME: &'static str = "hephaestus";

    /// Initializes a fresh Hephaestus BLAKE3 CAS store directory.
    #[must_use]
    pub fn init(store_path: &Path) -> Self {
        let cas_dir = store_path.join("cas");
        let _ = std::fs::create_dir_all(&cas_dir);
        let backend = Self::load(store_path);
        let (empty_bytes, empty_digest) = empty_tree_bytes_and_digest();
        let _ = write_local_cas(&cas_dir, &empty_digest, &empty_bytes);
        backend
    }

    /// Loads an existing Hephaestus BLAKE3 CAS store directory.
    #[must_use]
    pub fn load(store_path: &Path) -> Self {
        let (_, empty_digest) = empty_tree_bytes_and_digest();
        Self {
            driver: CasDriver::LocalDir(store_path.join("cas")),
            root_commit_id: CommitId::from_bytes(&[0u8; COMMIT_ID_LENGTH]),
            root_change_id: ChangeId::from_bytes(&[0u8; CHANGE_ID_LENGTH]),
            empty_tree_id: TreeId::new(empty_digest.0.to_vec()),
            files_written: AtomicU64::new(0),
            chunks_written: AtomicU64::new(0),
            commits_written: AtomicU64::new(0),
        }
    }

    /// Constructs a [`HephaestusBackend`] wired directly to [`CatalogStore`] + [`ObjectBackend`].
    #[must_use]
    pub fn with_cas_ports(catalog: Arc<dyn CatalogStore>, objects: Arc<dyn ObjectBackend>) -> Self {
        let (_, empty_digest) = empty_tree_bytes_and_digest();
        Self {
            driver: CasDriver::Ports { catalog, objects },
            root_commit_id: CommitId::from_bytes(&[0u8; COMMIT_ID_LENGTH]),
            root_change_id: ChangeId::from_bytes(&[0u8; CHANGE_ID_LENGTH]),
            empty_tree_id: TreeId::new(empty_digest.0.to_vec()),
            files_written: AtomicU64::new(0),
            chunks_written: AtomicU64::new(0),
            commits_written: AtomicU64::new(0),
        }
    }

    /// Number of file objects written through this backend instance.
    #[must_use]
    pub fn files_written(&self) -> u64 {
        self.files_written.load(Ordering::Relaxed)
    }

    /// Number of FastCDC chunks written through this backend instance.
    #[must_use]
    pub fn chunks_written(&self) -> u64 {
        self.chunks_written.load(Ordering::Relaxed)
    }

    /// Number of commits written through this backend instance.
    #[must_use]
    pub fn commits_written(&self) -> u64 {
        self.commits_written.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Backend for HephaestusBackend {
    fn name(&self) -> &str {
        Self::NAME
    }
    fn commit_id_length(&self) -> usize {
        COMMIT_ID_LENGTH
    }
    fn change_id_length(&self) -> usize {
        CHANGE_ID_LENGTH
    }
    fn root_commit_id(&self) -> &CommitId {
        &self.root_commit_id
    }
    fn root_change_id(&self) -> &ChangeId {
        &self.root_change_id
    }
    fn empty_tree_id(&self) -> &TreeId {
        &self.empty_tree_id
    }
    fn concurrency(&self) -> usize {
        16
    }

    async fn read_file(
        &self,
        _path: &RepoPath,
        id: &FileId,
    ) -> BackendResult<Pin<Box<dyn AsyncRead + Send>>> {
        let manifest_digest = id_to_digest(id)?;
        let raw_manifest = self
            .driver
            .get(&manifest_digest)
            .await?
            .ok_or_else(|| not_found_err(id))?;
        let manifest: CasFileManifest = serde_json::from_slice(&raw_manifest)
            .map_err(|e| other_err(format!("decode file manifest: {e}")))?;
        let mut out = Vec::with_capacity(manifest.total_len as usize);
        for chunk_hex in &manifest.chunks {
            let chunk_digest =
                BlobDigest::from_hex(chunk_hex).map_err(|e| other_err(e.to_string()))?;
            let chunk = self
                .driver
                .get(&chunk_digest)
                .await?
                .ok_or_else(|| not_found_err(id))?;
            out.extend_from_slice(&chunk);
        }
        Ok(Box::pin(Cursor::new(out)))
    }

    async fn write_file(
        &self,
        _path: &RepoPath,
        contents: &mut (dyn AsyncRead + Send + Unpin),
    ) -> BackendResult<FileId> {
        let mut raw = Vec::new();
        contents
            .read_to_end(&mut raw)
            .await
            .map_err(|e| other_err(format!("read write_file stream: {e}")))?;
        let chunks = chunk_bytes(&raw);
        let mut chunk_hashes = Vec::with_capacity(chunks.len());
        for ch in &chunks {
            let d = self.driver.put(&raw[ch.offset..ch.offset + ch.len]).await?;
            chunk_hashes.push(d.to_hex());
        }
        let manifest = CasFileManifest {
            total_len: raw.len() as u64,
            chunks: chunk_hashes,
        };
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| other_err(format!("encode manifest: {e}")))?;
        let manifest_digest = self.driver.put(&manifest_bytes).await?;
        self.files_written.fetch_add(1, Ordering::Relaxed);
        self.chunks_written
            .fetch_add(chunks.len() as u64, Ordering::Relaxed);
        Ok(FileId::new(manifest_digest.0.to_vec()))
    }

    async fn read_symlink(&self, _path: &RepoPath, id: &SymlinkId) -> BackendResult<String> {
        let d = id_to_digest(id)?;
        let bytes = self
            .driver
            .get(&d)
            .await?
            .ok_or_else(|| not_found_err(id))?;
        String::from_utf8(bytes).map_err(|e| other_err(format!("invalid symlink utf8: {e}")))
    }

    async fn write_symlink(&self, _path: &RepoPath, target: &str) -> BackendResult<SymlinkId> {
        let d = self.driver.put(target.as_bytes()).await?;
        Ok(SymlinkId::new(d.0.to_vec()))
    }

    async fn read_copy(&self, _id: &CopyId) -> BackendResult<CopyHistory> {
        Err(BackendError::Unsupported(
            "hephaestus backend does not track copy histories".into(),
        ))
    }

    async fn write_copy(&self, _contents: &CopyHistory) -> BackendResult<CopyId> {
        Err(BackendError::Unsupported(
            "hephaestus backend does not track copy histories".into(),
        ))
    }

    async fn get_related_copies(&self, _copy_id: &CopyId) -> BackendResult<Vec<RelatedCopy>> {
        Err(BackendError::Unsupported(
            "hephaestus backend does not track copy histories".into(),
        ))
    }

    async fn read_tree(&self, _path: &RepoPath, id: &TreeId) -> BackendResult<Tree> {
        if *id == self.empty_tree_id {
            return Ok(Tree::default());
        }
        let d = id_to_digest(id)?;
        let bytes = self
            .driver
            .get(&d)
            .await?
            .ok_or_else(|| not_found_err(id))?;
        decode_tree(&bytes)
    }

    async fn write_tree(&self, _path: &RepoPath, tree: &Tree) -> BackendResult<TreeId> {
        let (bytes, _) = encode_tree(tree)?;
        let d = self.driver.put(&bytes).await?;
        Ok(TreeId::new(d.0.to_vec()))
    }

    async fn read_commit(&self, id: &CommitId) -> BackendResult<Commit> {
        if *id == self.root_commit_id {
            return Ok(make_root_commit(
                self.root_change_id.clone(),
                self.empty_tree_id.clone(),
            ));
        }
        let d = id_to_digest(id)?;
        let bytes = self
            .driver
            .get(&d)
            .await?
            .ok_or_else(|| not_found_err(id))?;
        decode_commit(&bytes)
    }

    async fn write_commit(
        &self,
        mut commit: Commit,
        sign_with: Option<&mut SigningFn>,
    ) -> BackendResult<(CommitId, Commit)> {
        if commit.parents.is_empty() {
            return Err(other_err("cannot write a commit with no parents"));
        }
        let (unsigned_bytes, _) = encode_commit(&commit, None)?;
        let final_bytes = if let Some(sign) = sign_with {
            let sig = sign(&unsigned_bytes).map_err(|e| other_err(e.to_string()))?;
            let (signed_bytes, _) = encode_commit(&commit, Some(&sig))?;
            commit.secure_sig = Some(SecureSig {
                data: unsigned_bytes,
                sig,
            });
            signed_bytes
        } else {
            unsigned_bytes
        };
        let d = self.driver.put(&final_bytes).await?;
        self.commits_written.fetch_add(1, Ordering::Relaxed);
        Ok((CommitId::new(d.0.to_vec()), commit))
    }

    fn get_copy_records(
        &self,
        _paths: Option<&[RepoPathBuf]>,
        _root: &CommitId,
        _head: &CommitId,
    ) -> BackendResult<BoxStream<'_, BackendResult<CopyRecord>>> {
        Ok(stream::empty().boxed())
    }

    async fn gc(&self, _heads: &[CommitId], _keep_newer: SystemTime) -> BackendResult<()> {
        Ok(())
    }
}

/// Returns [`StoreFactories`] pre-populated with Jujutsu defaults plus [`HephaestusBackend`].
#[must_use]
pub fn hephaestus_store_factories() -> StoreFactories {
    let mut factories = default_backend_factories();
    factories.add_backend(
        HephaestusBackend::NAME,
        Box::new(|_settings, store_path| Ok(Box::new(HephaestusBackend::load(store_path)))),
    );
    factories
}

/// Returns [`StoreFactories`] registering [`HephaestusBackend`] backed by live CAS ports.
#[must_use]
pub fn hephaestus_store_factories_with_cas(
    catalog: Arc<dyn CatalogStore>,
    objects: Arc<dyn ObjectBackend>,
) -> StoreFactories {
    let mut factories = default_backend_factories();
    factories.add_backend(
        HephaestusBackend::NAME,
        Box::new(move |_settings, _store_path| {
            Ok(Box::new(HephaestusBackend::with_cas_ports(
                Arc::clone(&catalog),
                Arc::clone(&objects),
            )))
        }),
    );
    factories
}
