//! Jujutsu (`jj-lib`) OpLog traversal and bookmark-to-CAS catalog indexing.

use crate::repo_ops::{JjRepoService, jj_err};
use futures::StreamExt as _;
use hephaestus_core::{BlobDigest, ChangeId as HepChangeId, CommitId as HepCommitId, OpId, RepoId};
use hephaestus_store::{CatalogStore, CommitRef, StoreError};
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_walk;
use jj_lib::repo::Repo as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Summary of an operation in the Jujutsu OpLog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JjOpSummary {
    /// Operation identifier hex string.
    pub op_id: String,
    /// Parent operation identifier hex strings.
    pub parent_op_ids: Vec<String>,
    /// Operation log description.
    pub description: String,
    /// Operation timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: i64,
}

impl JjRepoService {
    /// Traverses recent `OpLog` entries in reverse topological order.
    pub async fn list_op_log(
        &self,
        root: &Path,
        limit: usize,
    ) -> Result<Vec<JjOpSummary>, StoreError> {
        let svc = self.clone();
        let root_buf = root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(svc.list_op_log_inner(&root_buf, limit))
        })
        .await
        .map_err(|e| jj_err("join list_op_log", e))?
    }

    async fn list_op_log_inner(
        &self,
        root: &Path,
        limit: usize,
    ) -> Result<Vec<JjOpSummary>, StoreError> {
        let repo = self.load_repo_local(root).await?;
        let mut out = Vec::new();
        let mut stream = std::pin::pin!(
            op_walk::walk_ancestors(std::slice::from_ref(repo.operation())).take(limit)
        );
        while let Some(op_res) = stream.next().await {
            let op = op_res.map_err(|e| jj_err("walk op_log", e))?;
            let meta = op.metadata();
            out.push(JjOpSummary {
                op_id: op.id().hex(),
                parent_op_ids: op.parent_ids().iter().map(|id| id.hex()).collect(),
                description: meta.description.clone(),
                timestamp_ms: meta.time.end.timestamp.0,
            });
        }
        Ok(out)
    }

    /// Indexes all local bookmarks and file trees from `root` into [`CatalogStore`] via `put_blob`.
    pub async fn index_bookmarks_into_catalog<F, Fut>(
        &self,
        root: &Path,
        repo_id: &RepoId,
        catalog: &dyn CatalogStore,
        mut put_blob: F,
    ) -> Result<Vec<CommitRef>, StoreError>
    where
        F: FnMut(Vec<u8>) -> Fut,
        Fut: core::future::Future<Output = Result<BlobDigest, StoreError>>,
    {
        let snapshots = self.collect_bookmark_snapshots(root).await?;
        let mut refs = Vec::with_capacity(snapshots.len());
        for (bookmark, change_id, commit_id, op_id, updated_ms, files) in snapshots {
            let mut tree_manifest = BTreeMap::new();
            for (path, bytes) in files {
                let digest = put_blob(bytes).await?;
                tree_manifest.insert(path, digest.to_hex());
            }
            let tree_bytes = serde_json::to_vec(&tree_manifest)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            let tree_digest = put_blob(tree_bytes).await?;
            let cref = CommitRef {
                repo_id: repo_id.clone(),
                bookmark,
                change_id,
                commit_id,
                op_id,
                tree_blob_hash: tree_digest.to_hex(),
                updated_ms,
            };
            catalog.upsert_ref(&cref).await?;
            refs.push(cref);
        }
        Ok(refs)
    }

    async fn collect_bookmark_snapshots(
        &self,
        root: &Path,
    ) -> Result<
        Vec<(
            String,
            HepChangeId,
            HepCommitId,
            OpId,
            u64,
            BTreeMap<String, Vec<u8>>,
        )>,
        StoreError,
    > {
        let svc = self.clone();
        let root_buf = root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(async move {
                let repo = svc.load_repo_local(&root_buf).await?;
                let op_id = OpId::parse(&repo.op_id().hex())?;
                let mut out = Vec::new();
                for (name, target) in repo.view().local_bookmarks() {
                    let Some(cid) = target.adds().flatten().next() else {
                        continue;
                    };
                    let commit = repo
                        .store()
                        .get_commit(cid)
                        .map_err(|e| jj_err("get bookmark commit", e))?;
                    let files = svc.read_commit_files_inner(&root_buf, &cid.hex()).await?;
                    out.push((
                        name.as_str().to_owned(),
                        HepChangeId::parse(&commit.change_id().hex())?,
                        HepCommitId::parse(&commit.id().hex())?,
                        op_id.clone(),
                        commit.committer().timestamp.timestamp.0.max(0) as u64,
                        files,
                    ));
                }
                Ok(out)
            })
        })
        .await
        .map_err(|e| jj_err("join collect_bookmark_snapshots", e))?
    }
}
