//! Git smart-HTTP compatibility bridge over `jj-lib` internal Git stores.

use crate::repo_ops::JjRepoService;
use jj_lib::git::{self, GitImportOptions};
use jj_lib::git_backend::GitBackend;
use jj_lib::repo::Repo as _;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use hephaestus_store::StoreError;

/// Encodes one Git pkt-line frame (`4`-hex length prefix including header).
#[must_use]
pub fn pkt_line_frame(payload: &[u8]) -> Vec<u8> {
    let total = payload.len() + 4;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(format!("{total:04x}").as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Bridges Git smart-HTTP (`info/refs`, `git-upload-pack`, `git-receive-pack`) into `jj-lib`.
#[derive(Clone)]
pub struct GitSmartHttpBridge {
    jj: JjRepoService,
}

impl GitSmartHttpBridge {
    /// Creates a bridge using `jj`.
    #[must_use]
    pub fn new(jj: JjRepoService) -> Self {
        Self { jj }
    }

    /// Resolves the bare Git object store directory inside a `jj` internal-git workspace.
    pub async fn resolve_git_dir(&self, repo_root: &Path) -> Result<PathBuf, StoreError> {
        let jj = self.jj.clone();
        let root_buf = repo_root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let repo = jj.load_repo_blocking(&root_buf)?;
            let git_backend = repo.store().backend_impl::<GitBackend>().ok_or_else(|| {
                StoreError::InvalidInput("repository is not backed by jj internal git".into())
            })?;
            Ok(git_backend.git_repo_path().to_path_buf())
        })
        .await
        .map_err(|e| StoreError::Backend(format!("join resolve_git_dir: {e}")))?
    }

    /// Serves `GET info/refs?service=git-upload-pack|git-receive-pack`.
    pub async fn info_refs(
        &self,
        repo_root: &Path,
        service: &str,
    ) -> Result<(String, Vec<u8>), StoreError> {
        let subcmd = map_git_service(service)?;
        let git_dir = self.resolve_git_dir(repo_root).await?;
        let out = Command::new("git")
            .args([subcmd, "--stateless-rpc", "--advertise-refs"])
            .arg(&git_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| StoreError::Backend(format!("spawn git {subcmd}: {e}")))?;
        if !out.status.success() {
            return Err(StoreError::Backend(format!(
                "git {subcmd} --advertise-refs failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let mut resp = pkt_line_frame(format!("# service={service}\n").as_bytes());
        resp.extend_from_slice(b"0000");
        resp.extend_from_slice(&out.stdout);
        let content_type = format!("application/x-{service}-advertisement");
        Ok((content_type, resp))
    }

    /// Serves `POST git-upload-pack` or `POST git-receive-pack`, syncing pushed Git refs into `jj`.
    pub async fn handle_rpc(
        &self,
        repo_root: &Path,
        service: &str,
        body: &[u8],
    ) -> Result<(String, Vec<u8>), StoreError> {
        let subcmd = map_git_service(service)?;
        let git_dir = self.resolve_git_dir(repo_root).await?;
        let mut child = Command::new("git")
            .args([subcmd, "--stateless-rpc"])
            .arg(&git_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| StoreError::Backend(format!("spawn git {subcmd}: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(body)
                .await
                .map_err(|e| StoreError::Backend(format!("write git stdin: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| StoreError::Backend(format!("wait git {subcmd}: {e}")))?;
        if !out.status.success() {
            return Err(StoreError::Backend(format!(
                "git {subcmd} --stateless-rpc failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        if service == "git-receive-pack" {
            self.import_git_refs_into_jj(repo_root).await?;
        }
        let content_type = format!("application/x-{service}-result");
        Ok((content_type, out.stdout))
    }

    /// Imports pushed Git refs from the internal bare repo into the Jujutsu OpLog.
    pub async fn import_git_refs_into_jj(&self, repo_root: &Path) -> Result<(), StoreError> {
        let jj = self.jj.clone();
        let root_buf = repo_root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(async move {
                let repo = jj.load_repo_local(&root_buf).await?;
                let mut tx = repo.start_transaction();
                let opts = GitImportOptions {
                    abandon_unreachable_commits: false,
                    record_synthetic_predecessors: true,
                    remote_auto_track_bookmarks: HashMap::new(),
                };
                let _stats = git::import_refs(tx.repo_mut(), &opts)
                    .await
                    .map_err(|e| StoreError::Backend(format!("jj git import_refs: {e}")))?;
                tx.commit("import git smart-http push")
                    .await
                    .map_err(|e| StoreError::Backend(format!("jj import commit: {e}")))?;
                Ok(())
            })
        })
        .await
        .map_err(|e| StoreError::Backend(format!("join import_git_refs: {e}")))?
    }
}

fn map_git_service(service: &str) -> Result<&'static str, StoreError> {
    match service {
        "git-upload-pack" => Ok("upload-pack"),
        "git-receive-pack" => Ok("receive-pack"),
        other => Err(StoreError::InvalidInput(format!(
            "unsupported git smart-http service `{other}`"
        ))),
    }
}
