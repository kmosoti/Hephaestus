//! Thread-safe SQLite WAL store dispatching all blocking I/O onto `tokio::task::spawn_blocking`.

use crate::catalog::{
    check_idempotent_sync, checkpoint_wal_sync, contains_sync, list_refs_sync, lookup_sync,
    put_inline_sync, record_bundle_sync, record_idempotent_sync, stats_sync,
    upsert_ref_idempotent_sync, upsert_ref_sync,
};
use crate::decision_logs::{
    append_decision_idempotent_sync, append_decision_sync, decision_inclusion_proof_sync,
    list_decisions_sync, verify_decisions_sync,
};
use crate::ltx::{export_ltx_snapshot_zstd_sync, ltx_snapshot_count_sync};
use crate::observation_logs::{
    append_observation_idempotent_sync, append_observation_sync, observation_inclusion_proof_sync,
    query_observations_sync, verify_observations_sync,
};
use crate::schema::{init_schema, io_err, query_page_size, sqlite_err};
use hephaestus_core::{
    BlobDigest, ChangeId, DecisionDraft, DecisionRecord, IdempotencyKey, MmrProof,
    ObservationDraft, ObservationFilter, ObservationRecord, RepoId, SealedBundle,
};
use hephaestus_store::{
    BlobLocation, BoxFuture, CatalogStats, CatalogStore, CommitRef, IdempotentReceipt, LogStore,
    StoreError,
};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct SqliteInner {
    conn: Connection,
    db_dir: Option<PathBuf>,
}

/// Authoritative SQLite WAL catalog, idempotency ledger, MMR node store, and log adapter.
#[derive(Clone)]
pub struct SqliteStore {
    inner: Arc<Mutex<SqliteInner>>,
}

impl SqliteStore {
    /// Opens or initializes a WAL-mode SQLite catalog at `path` (`page_size = 16384`).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let p = path.as_ref();
        if let Some(parent) = p.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let conn = Connection::open(p).map_err(sqlite_err)?;
        init_schema(&conn)?;
        let db_dir = p.parent().map(Path::to_path_buf);
        Ok(Self {
            inner: Arc::new(Mutex::new(SqliteInner { conn, db_dir })),
        })
    }

    /// Opens an ephemeral in-memory SQLite database (primarily for tests).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(sqlite_err)?;
        init_schema(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(SqliteInner { conn, db_dir: None })),
        })
    }

    /// Returns the active SQLite `PRAGMA page_size`.
    pub fn page_size(&self) -> Result<u32, StoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| StoreError::Backend("sqlite mutex poisoned".into()))?;
        query_page_size(&guard.conn)
    }

    async fn run_blocking<T, F>(&self, op: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut SqliteInner) -> Result<T, StoreError> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner
                .lock()
                .map_err(|_| StoreError::Backend("sqlite mutex poisoned".into()))?;
            op(&mut guard)
        })
        .await
        .map_err(|e| StoreError::Backend(format!("sqlite blocking task join: {e}")))?
    }

    /// Atomically checks idempotency, upserts `commit_ref`, and records `ack_payload`
    /// inside a single `BEGIN IMMEDIATE` transaction.
    pub async fn upsert_ref_idempotent(
        &self,
        commit_ref: &CommitRef,
        key: &IdempotencyKey,
        ack_payload: &[u8],
        now_ms: u64,
    ) -> Result<IdempotentReceipt, StoreError> {
        let (cref, k, ack) = (commit_ref.clone(), key.clone(), ack_payload.to_vec());
        self.run_blocking(move |st| {
            upsert_ref_idempotent_sync(&mut st.conn, &cref, &k, &ack, now_ms)
        })
        .await
    }

    /// Atomically checks idempotency, appends a hash-chained + MMR-committed Decision record,
    /// and persists its receipt in one `BEGIN IMMEDIATE` transaction.
    pub async fn append_decision_idempotent(
        &self,
        repo_id: &RepoId,
        draft: DecisionDraft,
        key: &IdempotencyKey,
        now_ms: u64,
    ) -> Result<(DecisionRecord, bool), StoreError> {
        let (repo, k) = (repo_id.clone(), key.clone());
        self.run_blocking(move |st| {
            append_decision_idempotent_sync(&mut st.conn, &repo, draft, &k, now_ms)
        })
        .await
    }

    /// Atomically checks idempotency, appends a hash-chained + MMR-committed Observation record,
    /// and persists its receipt in one `BEGIN IMMEDIATE` transaction.
    pub async fn append_observation_idempotent(
        &self,
        repo_id: &RepoId,
        draft: ObservationDraft,
        key: &IdempotencyKey,
        now_ms: u64,
    ) -> Result<(ObservationRecord, bool), StoreError> {
        let (repo, k) = (repo_id.clone(), key.clone());
        self.run_blocking(move |st| {
            append_observation_idempotent_sync(&mut st.conn, &repo, draft, &k, now_ms)
        })
        .await
    }

    /// Queries an `O(log N)` MMR inclusion proof for Decision record `seq` in `repo_id`.
    pub async fn decision_inclusion_proof(
        &self,
        repo_id: &RepoId,
        seq: u64,
    ) -> Result<MmrProof, StoreError> {
        let repo = repo_id.clone();
        self.run_blocking(move |st| decision_inclusion_proof_sync(&st.conn, &repo, seq))
            .await
    }

    /// Queries an `O(log N)` MMR inclusion proof for Observation record `seq` in `repo_id`.
    pub async fn observation_inclusion_proof(
        &self,
        repo_id: &RepoId,
        seq: u64,
    ) -> Result<MmrProof, StoreError> {
        let repo = repo_id.clone();
        self.run_blocking(move |st| observation_inclusion_proof_sync(&st.conn, &repo, seq))
            .await
    }

    /// Returns total recorded rows in `ltx_snapshots`.
    pub async fn ltx_snapshot_count(&self) -> Result<u64, StoreError> {
        self.run_blocking(|st| ltx_snapshot_count_sync(&st.conn))
            .await
    }
}

impl CatalogStore for SqliteStore {
    fn put_inline<'a>(
        &'a self,
        digest: &'a BlobDigest,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let d = *digest;
        let payload = data.to_vec();
        Box::pin(async move {
            self.run_blocking(move |st| put_inline_sync(&st.conn, &d, &payload))
                .await
        })
    }

    fn contains_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        let d = *digest;
        Box::pin(async move {
            self.run_blocking(move |st| contains_sync(&st.conn, &d))
                .await
        })
    }

    fn lookup_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<Option<BlobLocation>, StoreError>> {
        let d = *digest;
        Box::pin(async move { self.run_blocking(move |st| lookup_sync(&st.conn, &d)).await })
    }

    fn record_bundle<'a>(
        &'a self,
        bundle: &'a SealedBundle,
        object_id: &'a str,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let b = bundle.clone();
        let oid = object_id.to_owned();
        Box::pin(async move {
            self.run_blocking(move |st| record_bundle_sync(&mut st.conn, &b, &oid))
                .await
        })
    }

    fn check_idempotent<'a>(
        &'a self,
        key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        let k = key.clone();
        Box::pin(async move {
            self.run_blocking(move |st| check_idempotent_sync(&st.conn, &k))
                .await
        })
    }

    fn record_idempotent<'a>(
        &'a self,
        key: &'a IdempotencyKey,
        ack_payload: &'a [u8],
        now_ms: u64,
    ) -> BoxFuture<'a, Result<IdempotentReceipt, StoreError>> {
        let k = key.clone();
        let ack = ack_payload.to_vec();
        Box::pin(async move {
            self.run_blocking(move |st| record_idempotent_sync(&mut st.conn, &k, &ack, now_ms))
                .await
        })
    }

    fn upsert_ref<'a>(
        &'a self,
        commit_ref: &'a CommitRef,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let cref = commit_ref.clone();
        Box::pin(async move {
            self.run_blocking(move |st| upsert_ref_sync(&st.conn, &cref))
                .await
        })
    }

    fn list_refs<'a>(
        &'a self,
        repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<Vec<CommitRef>, StoreError>> {
        let repo = repo_id.clone();
        Box::pin(async move {
            self.run_blocking(move |st| list_refs_sync(&st.conn, &repo))
                .await
        })
    }

    fn stats(&self) -> BoxFuture<'_, Result<CatalogStats, StoreError>> {
        Box::pin(async move { self.run_blocking(|st| stats_sync(&st.conn)).await })
    }

    fn checkpoint_wal(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async move { self.run_blocking(|st| checkpoint_wal_sync(&st.conn)).await })
    }

    fn export_ltx_snapshot_zstd(&self) -> BoxFuture<'_, Result<Vec<u8>, StoreError>> {
        Box::pin(async move {
            self.run_blocking(|st| export_ltx_snapshot_zstd_sync(&st.conn, st.db_dir.as_deref()))
                .await
        })
    }
}

impl LogStore for SqliteStore {
    fn append_decision<'a>(
        &'a self,
        repo_id: &'a RepoId,
        draft: DecisionDraft,
    ) -> BoxFuture<'a, Result<DecisionRecord, StoreError>> {
        let repo = repo_id.clone();
        Box::pin(async move {
            self.run_blocking(move |st| append_decision_sync(&mut st.conn, &repo, draft))
                .await
        })
    }

    fn list_decisions<'a>(
        &'a self,
        repo_id: &'a RepoId,
        change_id: Option<&'a ChangeId>,
    ) -> BoxFuture<'a, Result<Vec<DecisionRecord>, StoreError>> {
        let repo = repo_id.clone();
        let ch = change_id.cloned();
        Box::pin(async move {
            self.run_blocking(move |st| list_decisions_sync(&st.conn, &repo, ch.as_ref()))
                .await
        })
    }

    fn verify_decisions<'a>(
        &'a self,
        repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<u64, StoreError>> {
        let repo = repo_id.clone();
        Box::pin(async move {
            self.run_blocking(move |st| verify_decisions_sync(&st.conn, &repo))
                .await
        })
    }

    fn append_observation<'a>(
        &'a self,
        repo_id: &'a RepoId,
        draft: ObservationDraft,
    ) -> BoxFuture<'a, Result<ObservationRecord, StoreError>> {
        let repo = repo_id.clone();
        Box::pin(async move {
            self.run_blocking(move |st| append_observation_sync(&mut st.conn, &repo, draft))
                .await
        })
    }

    fn query_observations<'a>(
        &'a self,
        repo_id: &'a RepoId,
        filter: &'a ObservationFilter,
    ) -> BoxFuture<'a, Result<Vec<ObservationRecord>, StoreError>> {
        let repo = repo_id.clone();
        let f = filter.clone();
        Box::pin(async move {
            self.run_blocking(move |st| query_observations_sync(&st.conn, &repo, &f))
                .await
        })
    }

    fn verify_observations<'a>(
        &'a self,
        repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<u64, StoreError>> {
        let repo = repo_id.clone();
        Box::pin(async move {
            self.run_blocking(move |st| verify_observations_sync(&st.conn, &repo))
                .await
        })
    }
}
