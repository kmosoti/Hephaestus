//! `CatalogStore` and `LogStore` trait implementations for [`crate::SqliteStore`].

use crate::catalog::{
    check_idempotent_sync, checkpoint_wal_sync, contains_sync, list_refs_sync, lookup_sync,
    put_inline_sync, record_bundle_sync, record_idempotent_sync, stats_sync,
    upsert_ref_idempotent_sync, upsert_ref_sync,
};
use crate::decision_logs::{append_decision_sync, query_decisions_sync, verify_decisions_sync};
use crate::ltx::export_ltx_snapshot_zstd_sync;
use crate::observation_logs::{
    append_observation_sync, query_observations_sync, verify_observations_sync,
};
use crate::store::SqliteStore;
use hephaestus_core::{
    BlobDigest, ChangeId, DecisionDraft, DecisionRecord, IdempotencyKey, ObservationDraft,
    ObservationFilter, ObservationRecord, RepoId, SealedBundle,
};
use hephaestus_store::{
    BlobLocation, BoxFuture, CatalogStats, CatalogStore, CommitRef, IdempotentReceipt, LogStore,
    StoreError,
};

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
            self.run_read_blocking(move |conn| contains_sync(conn, &d))
                .await
        })
    }

    fn lookup_blob<'a>(
        &'a self,
        digest: &'a BlobDigest,
    ) -> BoxFuture<'a, Result<Option<BlobLocation>, StoreError>> {
        let d = *digest;
        Box::pin(async move {
            self.run_read_blocking(move |conn| lookup_sync(conn, &d))
                .await
        })
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
            self.run_read_blocking(move |conn| check_idempotent_sync(conn, &k))
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
            self.run_read_blocking(move |conn| list_refs_sync(conn, &repo))
                .await
        })
    }

    fn stats(&self) -> BoxFuture<'_, Result<CatalogStats, StoreError>> {
        Box::pin(async move { self.run_read_blocking(stats_sync).await })
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
            self.run_read_blocking(move |conn| {
                query_decisions_sync(conn, &repo, ch.as_ref(), None, None)
            })
            .await
        })
    }

    fn verify_decisions<'a>(
        &'a self,
        repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<u64, StoreError>> {
        let repo = repo_id.clone();
        Box::pin(async move {
            self.run_verify_blocking(move |conn| verify_decisions_sync(conn, &repo))
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
            self.run_read_blocking(move |conn| query_observations_sync(conn, &repo, &f))
                .await
        })
    }

    fn verify_observations<'a>(
        &'a self,
        repo_id: &'a RepoId,
    ) -> BoxFuture<'a, Result<u64, StoreError>> {
        let repo = repo_id.clone();
        Box::pin(async move {
            self.run_verify_blocking(move |conn| verify_observations_sync(conn, &repo))
                .await
        })
    }
}

impl SqliteStore {
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
}
