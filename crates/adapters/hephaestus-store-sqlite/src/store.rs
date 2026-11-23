//! Thread-safe SQLite WAL store dispatching blocking I/O onto `tokio::task::spawn_blocking`,
//! isolating read/verification queries onto a bounded read-only WAL connection so writes do not starve.

use crate::decision_logs::{
    append_decision_idempotent_sync, decision_inclusion_proof_sync, query_decisions_sync,
};
use crate::ltx::{latest_ltx_snapshot_meta_sync, ltx_snapshot_count_sync};
use crate::observation_logs::{
    append_observation_idempotent_sync, observation_inclusion_proof_sync,
};
use crate::schema::{init_schema, io_err, query_page_size, sqlite_err};
use hephaestus_core::{
    ChangeId, DecisionDraft, DecisionRecord, IdempotencyKey, MmrProof, ObservationDraft,
    ObservationRecord, RepoId,
};
use hephaestus_store::{SnapshotMetadata, StoreError};
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

const MAX_CONCURRENT_SQLITE_READS: usize = 16;
const MAX_CONCURRENT_SQLITE_VERIFIES: usize = 2;
const READ_PERMIT_WAIT: Duration = Duration::from_millis(100);

pub(crate) struct SqliteInner {
    pub(crate) conn: Connection,
    pub(crate) db_dir: Option<PathBuf>,
}

/// Authoritative SQLite WAL catalog, idempotency ledger, MMR node store, and log adapter.
#[derive(Clone)]
pub struct SqliteStore {
    inner: Arc<Mutex<SqliteInner>>,
    read_conn: Option<Arc<Mutex<Connection>>>,
    read_sem: Arc<Semaphore>,
    verify_sem: Arc<Semaphore>,
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
        let rconn = Connection::open_with_flags(
            p,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sqlite_err)?;
        rconn
            .execute_batch("PRAGMA busy_timeout = 5000; PRAGMA query_only = ON;")
            .map_err(sqlite_err)?;
        let db_dir = p.parent().map(Path::to_path_buf);
        Ok(Self {
            inner: Arc::new(Mutex::new(SqliteInner { conn, db_dir })),
            read_conn: Some(Arc::new(Mutex::new(rconn))),
            read_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_SQLITE_READS)),
            verify_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_SQLITE_VERIFIES)),
        })
    }

    /// Opens an ephemeral in-memory SQLite database (primarily for tests).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(sqlite_err)?;
        init_schema(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(SqliteInner { conn, db_dir: None })),
            read_conn: None,
            read_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_SQLITE_READS)),
            verify_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_SQLITE_VERIFIES)),
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

    pub(crate) async fn run_blocking<T, F>(&self, op: F) -> Result<T, StoreError>
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

    pub(crate) async fn run_read_blocking<T, F>(&self, op: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let _permit =
            tokio::time::timeout(READ_PERMIT_WAIT, Arc::clone(&self.read_sem).acquire_owned())
                .await
                .map_err(|_| {
                    StoreError::RateLimited("sqlite read concurrency limit exceeded".into())
                })?
                .map_err(|_| StoreError::Backend("sqlite read semaphore closed".into()))?;
        let read_conn = self.read_conn.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            if let Some(rc) = read_conn {
                let guard = rc
                    .lock()
                    .map_err(|_| StoreError::Backend("sqlite read mutex poisoned".into()))?;
                op(&guard)
            } else {
                let guard = inner
                    .lock()
                    .map_err(|_| StoreError::Backend("sqlite mutex poisoned".into()))?;
                op(&guard.conn)
            }
        })
        .await
        .map_err(|e| StoreError::Backend(format!("sqlite blocking task join: {e}")))?
    }

    pub(crate) async fn run_verify_blocking<T, F>(&self, op: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let _vpermit = Arc::clone(&self.verify_sem)
            .try_acquire_owned()
            .map_err(|_| {
                StoreError::RateLimited("sqlite verification concurrency limit exceeded".into())
            })?;
        self.run_read_blocking(op).await
    }

    /// Queries paginated Decision Log records for `repo_id` with optional `change_id`,
    /// `since_seq` cursor, and bounded `limit`.
    pub async fn query_decisions(
        &self,
        repo_id: &RepoId,
        change_id: Option<&ChangeId>,
        since_seq: Option<u64>,
        limit: Option<usize>,
    ) -> Result<Vec<DecisionRecord>, StoreError> {
        let repo = repo_id.clone();
        let ch = change_id.cloned();
        self.run_read_blocking(move |conn| {
            query_decisions_sync(conn, &repo, ch.as_ref(), since_seq, limit)
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
        self.run_read_blocking(move |conn| decision_inclusion_proof_sync(conn, &repo, seq))
            .await
    }

    /// Queries an `O(log N)` MMR inclusion proof for Observation record `seq` in `repo_id`.
    pub async fn observation_inclusion_proof(
        &self,
        repo_id: &RepoId,
        seq: u64,
    ) -> Result<MmrProof, StoreError> {
        let repo = repo_id.clone();
        self.run_read_blocking(move |conn| observation_inclusion_proof_sync(conn, &repo, seq))
            .await
    }

    /// Returns total recorded rows in `ltx_snapshots`.
    pub async fn ltx_snapshot_count(&self) -> Result<u64, StoreError> {
        self.run_read_blocking(ltx_snapshot_count_sync).await
    }

    /// Returns metadata for the latest recorded `"LTX1"` snapshot, if any.
    pub async fn latest_ltx_snapshot_meta(&self) -> Result<Option<SnapshotMetadata>, StoreError> {
        self.run_read_blocking(latest_ltx_snapshot_meta_sync).await
    }
}
