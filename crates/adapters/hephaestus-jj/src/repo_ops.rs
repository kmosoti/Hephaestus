//! Jujutsu (`jj-lib`) repository lifecycle, commit creation, OpLog traversal, and CAS indexing.

use crate::backend::{HephaestusBackend, hephaestus_store_factories};
use futures::{AsyncReadExt as _, StreamExt as _};
use hephaestus_store::StoreError;
use jj_lib::backend::{CopyId, TreeValue};
use jj_lib::config::{ConfigLayer, ConfigSource, StackedConfig};
use jj_lib::default_backend_factories::default_working_copy_factories;
use jj_lib::git;
use jj_lib::git_backend::GitBackend;
use jj_lib::merged_tree_builder::MergedTreeBuilder;
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::{RefName, WorkspaceName, WorkspaceNameBuf};
use jj_lib::repo::{BackendInitializer, ReadonlyRepo, Repo as _, RepoLoader};
use jj_lib::repo_path::RepoPathBuf;
use jj_lib::settings::UserSettings;
use jj_lib::signing_factory::signer_from_settings;
use jj_lib::workspace::{DefaultWorkspaceLoaderFactory, Workspace, WorkspaceLoaderFactory as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

pub(crate) fn jj_err(ctx: &str, err: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(format!("jj {ctx}: {err}"))
}

/// Builds deterministic [`UserSettings`] without reading host `$HOME` config files.
pub fn default_user_settings(name: &str, email: &str) -> Result<UserSettings, StoreError> {
    let mut cfg = StackedConfig::with_defaults();
    let mut layer = ConfigLayer::empty(ConfigSource::User);
    layer
        .set_value("user.name", name)
        .map_err(|e| jj_err("set user.name", e))?;
    layer
        .set_value("user.email", email)
        .map_err(|e| jj_err("set user.email", e))?;
    cfg.add_layer(layer);
    UserSettings::from_config_and_home_dir(cfg, None).map_err(|e| jj_err("user settings", e))
}

/// File tree and bookmark specification for creating a commit via [`JjRepoService`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JjCommitInput {
    /// Target bookmark name (e.g., `main`).
    pub bookmark: String,
    /// Commit description message.
    pub description: String,
    /// Repository-relative file paths mapped to raw UTF-8/binary contents.
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Result of committing a tree and updating a bookmark inside `jj-lib`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JjCommitResult {
    /// Jujutsu `ChangeId` hex string.
    pub change_id: String,
    /// Jujutsu `CommitId` hex string.
    pub commit_id: String,
    /// Jujutsu `OpId` hex string.
    pub op_id: String,
    /// Number of files written into the commit tree.
    pub files_written: usize,
}

/// High-level `jj-lib` repository coordinator supporting [`HephaestusBackend`] and `GitBackend`.
#[derive(Clone)]
pub struct JjRepoService {
    settings: UserSettings,
}

impl JjRepoService {
    /// Constructs a service using deterministic user settings.
    pub fn new(user_name: &str, user_email: &str) -> Result<Self, StoreError> {
        Ok(Self {
            settings: default_user_settings(user_name, user_email)?,
        })
    }

    /// Returns the configured [`UserSettings`].
    #[must_use]
    pub fn settings(&self) -> &UserSettings {
        &self.settings
    }

    /// Initializes a workspace backed by [`HephaestusBackend`].
    pub async fn init_hephaestus_repo(&self, root: &Path) -> Result<Arc<ReadonlyRepo>, StoreError> {
        std::fs::create_dir_all(root).map_err(|e| jj_err("create repo root", e))?;
        let init: &BackendInitializer = &|_settings, store_path| {
            Ok(Box::new(HephaestusBackend::init(store_path)) as Box<dyn jj_lib::backend::Backend>)
        };
        let signer = signer_from_settings(&self.settings).map_err(|e| jj_err("signer", e))?;
        let (_ws, repo) = Workspace::init_with_backend(
            &self.settings,
            root,
            WorkspaceName::DEFAULT,
            init,
            signer,
        )
        .await
        .map_err(|e| jj_err("init hephaestus workspace", e))?;
        Ok(repo)
    }

    /// Initializes a workspace backed by internal Git (`.jj/repo/store/git`) for Git smart-HTTP.
    pub async fn init_internal_git_repo(
        &self,
        root: &Path,
    ) -> Result<Arc<ReadonlyRepo>, StoreError> {
        std::fs::create_dir_all(root).map_err(|e| jj_err("create git repo root", e))?;
        let (_ws, repo) = Workspace::init_internal_git(
            &self.settings,
            root,
            WorkspaceName::DEFAULT,
            gix::hash::Kind::Sha1,
        )
        .await
        .map_err(|e| jj_err("init internal git workspace", e))?;
        Ok(repo)
    }

    fn open_repo_loader(&self, root: &Path) -> Result<(WorkspaceNameBuf, RepoLoader), StoreError> {
        let factories = hephaestus_store_factories();
        let wc_factories = default_working_copy_factories();
        let loader = DefaultWorkspaceLoaderFactory
            .create(root)
            .map_err(|e| jj_err("create workspace loader", e))?;
        let ws = loader
            .load(&self.settings, &factories, &wc_factories)
            .map_err(|e| jj_err("load workspace", e))?;
        Ok((ws.workspace_name().to_owned(), ws.repo_loader().clone()))
    }

    pub(crate) async fn load_repo_local(
        &self,
        root: &Path,
    ) -> Result<Arc<ReadonlyRepo>, StoreError> {
        let (ws_name, repo_loader) = self.open_repo_loader(root)?;
        repo_loader
            .load_at_head(Some(&ws_name))
            .await
            .map_err(|e| jj_err("load head", e))
    }

    /// Loads an existing workspace and latest repository head synchronously on the current thread.
    pub fn load_repo_blocking(&self, root: &Path) -> Result<Arc<ReadonlyRepo>, StoreError> {
        futures::executor::block_on(self.load_repo_local(root))
    }

    /// Loads an existing workspace and latest repository head on Tokio's blocking pool.
    pub async fn load_repo(&self, root: &Path) -> Result<Arc<ReadonlyRepo>, StoreError> {
        let svc = self.clone();
        let root_buf = root.to_path_buf();
        tokio::task::spawn_blocking(move || svc.load_repo_blocking(&root_buf))
            .await
            .map_err(|e| jj_err("join load_repo", e))?
    }

    /// Writes `input.files` into a new `jj` commit, moves `input.bookmark`, exports Git refs
    /// if using `GitBackend`, and commits the transaction.
    pub async fn commit_files_and_bookmark(
        &self,
        root: &Path,
        input: &JjCommitInput,
    ) -> Result<JjCommitResult, StoreError> {
        let svc = self.clone();
        let root_buf = root.to_path_buf();
        let input_owned = input.clone();
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(
                svc.commit_files_and_bookmark_inner(&root_buf, &input_owned),
            )
        })
        .await
        .map_err(|e| jj_err("join commit", e))?
    }

    async fn commit_files_and_bookmark_inner(
        &self,
        root: &Path,
        input: &JjCommitInput,
    ) -> Result<JjCommitResult, StoreError> {
        let repo = self.load_repo_local(root).await?;
        let store = repo.store();
        let bm_name = RefName::new(&input.bookmark);
        let parent_id = repo
            .view()
            .get_local_bookmark(bm_name)
            .adds()
            .flatten()
            .next()
            .cloned()
            .unwrap_or_else(|| store.root_commit_id().clone());

        let base_tree = if parent_id == *store.root_commit_id() {
            store.empty_merged_tree()
        } else {
            store
                .get_commit(&parent_id)
                .map_err(|e| jj_err("get parent commit", e))?
                .tree()
        };

        let mut tree_builder = MergedTreeBuilder::new(base_tree);
        for (rel_path, bytes) in &input.files {
            let repo_path = RepoPathBuf::from_internal_string(rel_path)
                .map_err(|e| jj_err("invalid repo path", e))?;
            let mut cursor = futures::io::Cursor::new(bytes.as_slice());
            let file_id = store
                .write_file(&repo_path, &mut cursor)
                .await
                .map_err(|e| jj_err("write file", e))?;
            tree_builder.set_or_remove(
                repo_path,
                Some(TreeValue::File {
                    id: file_id,
                    executable: false,
                    copy_id: CopyId::placeholder(),
                }),
            );
        }
        let new_tree = tree_builder
            .write_tree()
            .await
            .map_err(|e| jj_err("write tree", e))?;

        let mut tx = repo.start_transaction();
        let commit = tx
            .repo_mut()
            .new_commit(vec![parent_id], new_tree)
            .set_description(&input.description)
            .write()
            .await
            .map_err(|e| jj_err("write commit", e))?;
        tx.repo_mut()
            .set_local_bookmark_target(bm_name, RefTarget::normal(commit.id().clone()));
        if let Some(git_backend) = store.backend_impl::<GitBackend>() {
            let _ = git::export_refs(tx.repo_mut()).map_err(|e| jj_err("export git refs", e))?;
            if input.bookmark == "main" {
                std::fs::write(
                    git_backend.git_repo_path().join("HEAD"),
                    "ref: refs/heads/main\n",
                )
                .map_err(|e| jj_err("set internal git HEAD", e))?;
            }
        }
        let updated_repo = tx
            .commit(format!("commit bookmark {}", input.bookmark))
            .await
            .map_err(|e| jj_err("commit tx", e))?;

        Ok(JjCommitResult {
            change_id: commit.change_id().hex(),
            commit_id: commit.id().hex(),
            op_id: updated_repo.op_id().hex(),
            files_written: input.files.len(),
        })
    }

    /// Reads all regular files from `commit_id_hex` via `jj-lib`.
    pub async fn read_commit_files(
        &self,
        root: &Path,
        commit_id_hex: &str,
    ) -> Result<BTreeMap<String, Vec<u8>>, StoreError> {
        let svc = self.clone();
        let root_buf = root.to_path_buf();
        let hex_owned = commit_id_hex.to_owned();
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(svc.read_commit_files_inner(&root_buf, &hex_owned))
        })
        .await
        .map_err(|e| jj_err("join read_commit_files", e))?
    }

    pub(crate) async fn read_commit_files_inner(
        &self,
        root: &Path,
        commit_id_hex: &str,
    ) -> Result<BTreeMap<String, Vec<u8>>, StoreError> {
        let repo = self.load_repo_local(root).await?;
        let raw_id = hex::decode(commit_id_hex)
            .map_err(|e| StoreError::InvalidInput(format!("invalid commit hex: {e}")))?;
        let commit_id = jj_lib::backend::CommitId::from_bytes(&raw_id);
        let commit = repo
            .store()
            .get_commit(&commit_id)
            .map_err(|e| jj_err("get commit", e))?;
        let tree = commit.tree();
        let mut entries = tree.entries();
        let mut out = BTreeMap::new();
        while let Some((path, value_res)) = entries.next().await {
            let value = value_res.map_err(|e| jj_err("tree entry", e))?;
            if let Some(Some(TreeValue::File { id, .. })) = value.as_resolved() {
                let mut reader = repo
                    .store()
                    .read_file(&path, id)
                    .await
                    .map_err(|e| jj_err("read file", e))?;
                let mut buf = Vec::new();
                reader
                    .read_to_end(&mut buf)
                    .await
                    .map_err(|e| jj_err("read file stream", e))?;
                out.insert(path.as_internal_file_string().to_owned(), buf);
            }
        }
        Ok(out)
    }
}
