//! Unified replication, CAS, atomic SQLite idempotency, Decision/Observation Log,
//! multi-repo Jujutsu sync, and background `"LTX1"` snapshot shipping engine.

use hephaestus_core::{
    BlobDigest, ChangeId, DecisionDraft, DecisionRecord, IdempotencyKey, ObservationDraft,
    ObservationFilter, ObservationRecord, RepoId, StreamKind,
};
use hephaestus_jj::{GitSmartHttpBridge, JjOpSummary, JjRepoService};
use hephaestus_store::{
    CatalogStats, CatalogStore, CommitRef, LogStore, PushWebhookEvent, StoreError, WebhookSink,
};
use hephaestus_store_object::PackedCasEngine;
use hephaestus_store_sqlite::SqliteStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().min(u128::from(u64::MAX)) as u64)
}

/// Validates a single-segment repository path parameter against `^[a-zA-Z0-9._-]+$`.
pub fn validate_git_repo_segment(repo: &str) -> Result<(), StoreError> {
    if repo.is_empty()
        || repo == "."
        || repo == ".."
        || !repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(StoreError::InvalidInput(format!(
            "invalid repository name `{repo}`: must match ^[a-zA-Z0-9._-]+$"
        )));
    }
    Ok(())
}

/// Composition engine wiring SQLite WAL catalog/logs, `PackedCasEngine`, webhooks, and `jj-lib`.
pub struct HephaestusEngine {
    sqlite: SqliteStore,
    cas: PackedCasEngine,
    webhook: Arc<dyn WebhookSink>,
    jj_service: JjRepoService,
    git_bridge: GitSmartHttpBridge,
    jj_repo_root: Option<PathBuf>,
    pub(crate) last_restored_txid: AtomicU64,
}

impl HephaestusEngine {
    /// Constructs a [`HephaestusEngine`].
    #[must_use]
    pub fn new(
        sqlite: SqliteStore,
        cas: PackedCasEngine,
        webhook: Arc<dyn WebhookSink>,
        jj_service: JjRepoService,
        jj_repo_root: Option<PathBuf>,
    ) -> Self {
        let git_bridge = GitSmartHttpBridge::new(jj_service.clone());
        Self {
            sqlite,
            cas,
            webhook,
            jj_service,
            git_bridge,
            jj_repo_root,
            last_restored_txid: AtomicU64::new(0),
        }
    }

    /// Returns the configured `jj` repository root directory, if any.
    #[must_use]
    pub fn jj_repo_root(&self) -> Option<&Path> {
        self.jj_repo_root.as_deref()
    }

    /// Resolves `{repo}` to `<jj_repo_root>/<repo>` in multi-repo mode or `<jj_repo_root>`
    /// when a single workspace is mounted directly at `jj_repo_root`.
    pub fn resolve_jj_repo(&self, repo_name: &str) -> Result<PathBuf, StoreError> {
        validate_git_repo_segment(repo_name)?;
        let root = self
            .jj_repo_root
            .as_deref()
            .ok_or_else(|| StoreError::NotFound("no jj repository configured".into()))?;
        let named = root.join(repo_name);
        if named.join(".jj").is_dir() {
            return Ok(named);
        }
        if root.join(".jj").is_dir() {
            return Ok(root.to_path_buf());
        }
        Err(StoreError::NotFound(format!(
            "jj repository `{repo_name}` not found"
        )))
    }

    /// Returns a reference to [`JjRepoService`].
    #[must_use]
    pub fn jj_service(&self) -> &JjRepoService {
        &self.jj_service
    }

    /// Returns a reference to [`GitSmartHttpBridge`].
    #[must_use]
    pub fn git_bridge(&self) -> &GitSmartHttpBridge {
        &self.git_bridge
    }

    /// Returns a reference to [`SqliteStore`].
    #[must_use]
    pub fn sqlite(&self) -> &SqliteStore {
        &self.sqlite
    }

    /// Returns a reference to [`PackedCasEngine`].
    #[must_use]
    pub fn cas(&self) -> &PackedCasEngine {
        &self.cas
    }

    /// Returns object backend kind string (`localfs`, `s3`, `gcs`, `google-drive`, `memory`).
    #[must_use]
    pub fn backend_kind(&self) -> &'static str {
        self.cas.object_backend().backend_kind()
    }

    /// Returns current SQLite catalog stats plus staged CAS bytes.
    pub async fn stats(&self) -> Result<(CatalogStats, usize), StoreError> {
        self.cas.stats().await
    }

    /// Stores a blob idempotently under `(repo_id, StreamKind::Blob, blake3_digest)`.
    pub async fn put_blob_idempotent(
        &self,
        repo_id: &RepoId,
        data: Vec<u8>,
        force_pack: bool,
    ) -> Result<(BlobDigest, bool), StoreError> {
        let digest = BlobDigest::of(&data);
        let key = IdempotencyKey {
            repo_id: repo_id.clone(),
            stream_kind: StreamKind::Blob,
            digest,
        };
        if self.sqlite.check_idempotent(&key).await?.is_some() {
            return Ok((digest, true));
        }
        let stored_digest = self.cas.put_blob(data, force_pack).await?;
        let receipt = self
            .sqlite
            .record_idempotent(&key, stored_digest.as_bytes(), now_unix_ms())
            .await?;
        Ok((stored_digest, receipt.already_applied))
    }

    /// Retrieves a blob by hex digest.
    pub async fn get_blob_hex(&self, digest_hex: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let digest = BlobDigest::from_hex(digest_hex)
            .map_err(|e| StoreError::InvalidInput(e.to_string()))?;
        self.cas.get_blob(&digest).await
    }

    /// Flushes staged blobs into a `GRNB0002` bundle on the object backend.
    pub async fn flush_bundle(&self) -> Result<Option<String>, StoreError> {
        self.cas.flush_bundle().await
    }

    /// Flushes staged bundles, atomically checks+writes ref+idempotency in one `BEGIN IMMEDIATE`
    /// transaction, and notifies the push webhook once.
    pub async fn push_ref_idempotent(
        &self,
        commit_ref: &CommitRef,
    ) -> Result<(bool, bool), StoreError> {
        let _ = self.cas.flush_bundle().await?;
        let canonical =
            serde_json::to_vec(commit_ref).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let key = IdempotencyKey {
            repo_id: commit_ref.repo_id.clone(),
            stream_kind: StreamKind::JjOp,
            digest: BlobDigest::of(&canonical),
        };
        let receipt = self
            .sqlite
            .upsert_ref_idempotent(commit_ref, &key, b"ref_committed", now_unix_ms())
            .await?;
        let notified = if receipt.already_applied {
            false
        } else {
            let ev = PushWebhookEvent {
                repo_id: commit_ref.repo_id.clone(),
                bookmark: commit_ref.bookmark.clone(),
                change_id: commit_ref.change_id.clone(),
                commit_id: commit_ref.commit_id.clone(),
                op_id: commit_ref.op_id.clone(),
                tree_blob_hash: commit_ref.tree_blob_hash.clone(),
            };
            self.webhook.notify_push(&ev).await.unwrap_or(false)
        };
        Ok((notified, receipt.already_applied))
    }

    /// Lists bookmark refs for `repo_id`.
    pub async fn list_refs(&self, repo_id: &RepoId) -> Result<Vec<CommitRef>, StoreError> {
        self.sqlite.list_refs(repo_id).await
    }

    /// Atomically appends a Decision Log entry inside a single `BEGIN IMMEDIATE` transaction.
    pub async fn append_decision_idempotent(
        &self,
        repo_id: &RepoId,
        draft: DecisionDraft,
    ) -> Result<(DecisionRecord, bool), StoreError> {
        let raw =
            serde_json::to_vec(&draft).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let key = IdempotencyKey {
            repo_id: repo_id.clone(),
            stream_kind: StreamKind::Decision,
            digest: BlobDigest::of(&raw),
        };
        self.sqlite
            .append_decision_idempotent(repo_id, draft, &key, now_unix_ms())
            .await
    }

    /// Lists Decision Log records for `repo_id`, optionally filtered by `ChangeId` (capped page).
    pub async fn list_decisions(
        &self,
        repo_id: &RepoId,
        change_id: Option<&ChangeId>,
    ) -> Result<Vec<DecisionRecord>, StoreError> {
        self.sqlite.list_decisions(repo_id, change_id).await
    }

    /// Queries paginated Decision Log records for `repo_id`.
    pub async fn query_decisions(
        &self,
        repo_id: &RepoId,
        change_id: Option<&ChangeId>,
        since_seq: Option<u64>,
        limit: Option<usize>,
    ) -> Result<Vec<DecisionRecord>, StoreError> {
        self.sqlite
            .query_decisions(repo_id, change_id, since_seq, limit)
            .await
    }

    /// Verifies `repo_id`'s Decision Log hash chain and MMR roots.
    pub async fn verify_decisions(&self, repo_id: &RepoId) -> Result<u64, StoreError> {
        self.sqlite.verify_decisions(repo_id).await
    }

    /// Atomically appends an Observation Log entry inside a single `BEGIN IMMEDIATE` transaction.
    pub async fn append_observation_idempotent(
        &self,
        repo_id: &RepoId,
        draft: ObservationDraft,
    ) -> Result<(ObservationRecord, bool), StoreError> {
        let raw =
            serde_json::to_vec(&draft).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let key = IdempotencyKey {
            repo_id: repo_id.clone(),
            stream_kind: StreamKind::Observation,
            digest: BlobDigest::of(&raw),
        };
        self.sqlite
            .append_observation_idempotent(repo_id, draft, &key, now_unix_ms())
            .await
    }

    /// Queries orthogonal Observation Log records matching `filter`.
    pub async fn query_observations(
        &self,
        repo_id: &RepoId,
        filter: &ObservationFilter,
    ) -> Result<Vec<ObservationRecord>, StoreError> {
        self.sqlite.query_observations(repo_id, filter).await
    }

    /// Verifies `repo_id`'s Observation Log hash chain and MMR roots.
    pub async fn verify_observations(&self, repo_id: &RepoId) -> Result<u64, StoreError> {
        self.sqlite.verify_observations(repo_id).await
    }

    /// Lists recent `jj` OpLog summaries from the configured repository root.
    pub async fn list_jj_ops(&self, limit: usize) -> Result<Vec<JjOpSummary>, StoreError> {
        let root = self
            .jj_repo_root
            .as_deref()
            .ok_or_else(|| StoreError::NotFound("no jj repository configured".into()))?;
        self.jj_service.list_op_log(root, limit).await
    }

    /// Indexes pushed `jj` bookmarks into CAS, flushes staged bundles, and notifies [`WebhookSink`].
    pub async fn sync_git_push_to_cas_and_notify(
        &self,
        repo_name: &str,
        repo_root: &Path,
    ) -> Result<usize, StoreError> {
        let repo_id = RepoId::parse(repo_name)?;
        let cas = &self.cas;
        let refs = self
            .jj_service
            .index_bookmarks_into_catalog(repo_root, &repo_id, &self.sqlite, |bytes| async move {
                cas.put_blob(bytes, false).await
            })
            .await?;
        let _ = self.cas.flush_bundle().await?;
        let mut notified = 0usize;
        for cref in &refs {
            let (sent, _) = self.push_ref_idempotent(cref).await?;
            if sent {
                notified += 1;
            }
        }
        Ok(notified)
    }

    /// Exports a real Zstd-compressed `"LTX1"` snapshot, records `ltx_snapshots`, and uploads it
    /// to [`hephaestus_store::ObjectBackend`].
    pub async fn ship_ltx_snapshot(&self) -> Result<String, StoreError> {
        self.ship_ltx_snapshot_manifest().await.map(|r| r.object_id)
    }
}

/// Spawns a background task shipping `"LTX1"` snapshots to [`hephaestus_store::ObjectBackend`]
/// on a fixed interval.
pub fn spawn_ltx_shipper(
    engine: Arc<HephaestusEngine>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let _ = engine.ship_ltx_snapshot().await;
        }
    })
}
