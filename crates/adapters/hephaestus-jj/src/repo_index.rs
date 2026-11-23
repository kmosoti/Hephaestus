//! Jujutsu (`jj-lib`) OpLog traversal and single-pass, changed-OID bookmark-to-CAS indexing.

use crate::repo_ops::{JjRepoService, jj_err};
use futures::{AsyncReadExt as _, StreamExt as _};
use hephaestus_core::{BlobDigest, ChangeId as HepChangeId, CommitId as HepCommitId, OpId, RepoId};
use hephaestus_store::{CatalogStore, CommitRef, StoreError};
use jj_lib::backend::TreeValue;
use jj_lib::merged_tree::MergedTree;
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_walk;
use jj_lib::repo::Repo as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

const MAX_OPLOG_LIMIT: usize = 1000;
const MAX_BOOKMARKS_PER_INDEX: usize = 4096;
const MAX_FILES_PER_INDEX: usize = 65_536;
const MAX_INDEX_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_UNIQUE_BYTES_PER_INDEX: usize = 256 * 1024 * 1024;

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

struct ChangedBookmark {
    bookmark: String,
    change_id: HepChangeId,
    commit_id: HepCommitId,
    op_id: OpId,
    updated_ms: u64,
    tree: MergedTree,
    tree_key: Option<Vec<u8>>,
}

async fn read_bounded_jj_file(
    repo: &jj_lib::repo::ReadonlyRepo,
    path: &jj_lib::repo_path::RepoPath,
    file_id: &jj_lib::backend::FileId,
) -> Result<Vec<u8>, StoreError> {
    let reader = repo
        .store()
        .read_file(path, file_id)
        .await
        .map_err(|e| jj_err("read file", e))?;
    let mut limited = reader.take((MAX_INDEX_FILE_BYTES as u64) + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .await
        .map_err(|e| jj_err("read file stream", e))?;
    if buf.len() > MAX_INDEX_FILE_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "indexed file exceeds maximum size of {MAX_INDEX_FILE_BYTES} bytes"
        )));
    }
    Ok(buf)
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
        let bounded = limit.min(MAX_OPLOG_LIMIT);
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(svc.list_op_log_inner(&root_buf, bounded))
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

    /// Indexes changed local bookmarks and deduplicated `FileId`s into [`CatalogStore`] via `put_blob`
    /// in a single bounded pass, committing ref updates only after all budgets succeed.
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
        let existing: HashMap<String, String> = catalog
            .list_refs(repo_id)
            .await?
            .into_iter()
            .map(|r| (r.bookmark, r.commit_id.as_str().to_owned()))
            .collect();

        let repo = self.load_repo(root).await?;
        let op_id = OpId::parse(&repo.op_id().hex())?;
        let mut bookmark_count = 0usize;
        let mut changed = Vec::new();

        for (name, target) in repo.view().local_bookmarks() {
            bookmark_count += 1;
            if bookmark_count > MAX_BOOKMARKS_PER_INDEX {
                return Err(StoreError::InvalidInput(format!(
                    "repository bookmark count exceeds limit of {MAX_BOOKMARKS_PER_INDEX}"
                )));
            }
            let Some(cid) = target.adds().flatten().next() else {
                continue;
            };
            let cid_hex = cid.hex();
            if existing
                .get(name.as_str())
                .is_some_and(|prev| prev == &cid_hex)
            {
                continue;
            }
            let commit = repo
                .store()
                .get_commit(cid)
                .map_err(|e| jj_err("get bookmark commit", e))?;
            let tree = commit.tree();
            let tree_key = tree
                .tree_ids()
                .as_resolved()
                .map(|id| id.as_bytes().to_vec());
            changed.push(ChangedBookmark {
                bookmark: name.as_str().to_owned(),
                change_id: HepChangeId::parse(&commit.change_id().hex())?,
                commit_id: HepCommitId::parse(&cid_hex)?,
                op_id: op_id.clone(),
                updated_ms: commit.committer().timestamp.timestamp.0.max(0) as u64,
                tree,
                tree_key,
            });
        }

        let mut seen_trees: HashMap<Vec<u8>, BlobDigest> = HashMap::new();
        let mut seen_files: HashMap<Vec<u8>, BlobDigest> = HashMap::new();
        let mut total_files = 0usize;
        let mut total_unique_bytes = 0usize;
        let mut pending_refs = Vec::with_capacity(changed.len());

        for bm in changed {
            let tree_digest = if let Some(key) = &bm.tree_key
                && let Some(&cached) = seen_trees.get(key)
            {
                cached
            } else {
                let mut tree_manifest = BTreeMap::new();
                let mut entries = bm.tree.entries();
                while let Some((path, value_res)) = entries.next().await {
                    let value = value_res.map_err(|e| jj_err("tree entry", e))?;
                    if let Some(Some(TreeValue::File { id, .. })) = value.as_resolved() {
                        total_files += 1;
                        if total_files > MAX_FILES_PER_INDEX {
                            return Err(StoreError::InvalidInput(format!(
                                "indexed file count exceeds limit of {MAX_FILES_PER_INDEX}"
                            )));
                        }
                        let file_key = id.as_bytes().to_vec();
                        let digest = if let Some(&d) = seen_files.get(&file_key) {
                            d
                        } else {
                            let bytes = read_bounded_jj_file(repo.as_ref(), &path, id).await?;
                            total_unique_bytes = total_unique_bytes
                                .checked_add(bytes.len())
                                .filter(|&n| n <= MAX_UNIQUE_BYTES_PER_INDEX)
                                .ok_or_else(|| {
                                    StoreError::InvalidInput(format!(
                                        "indexed push exceeds {MAX_UNIQUE_BYTES_PER_INDEX} byte budget"
                                    ))
                                })?;
                            let d = put_blob(bytes).await?;
                            seen_files.insert(file_key, d);
                            d
                        };
                        tree_manifest
                            .insert(path.as_internal_file_string().to_owned(), digest.to_hex());
                    }
                }
                let tree_bytes = serde_json::to_vec(&tree_manifest)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                let td = put_blob(tree_bytes).await?;
                if let Some(key) = bm.tree_key {
                    seen_trees.insert(key, td);
                }
                td
            };
            pending_refs.push(CommitRef {
                repo_id: repo_id.clone(),
                bookmark: bm.bookmark,
                change_id: bm.change_id,
                commit_id: bm.commit_id,
                op_id: bm.op_id,
                tree_blob_hash: tree_digest.to_hex(),
                updated_ms: bm.updated_ms,
            });
        }

        for cref in &pending_refs {
            catalog.upsert_ref(cref).await?;
        }
        Ok(pending_refs)
    }
}
