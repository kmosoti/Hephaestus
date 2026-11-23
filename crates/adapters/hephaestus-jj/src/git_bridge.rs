//! Git smart-HTTP compatibility bridge over `jj-lib` internal Git stores.

use crate::repo_ops::JjRepoService;
use jj_lib::git::{self, GitImportOptions};
use jj_lib::git_backend::GitBackend;
use jj_lib::repo::Repo as _;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use hephaestus_store::StoreError;

const GIT_CMD_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_GIT_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;

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
        let mut child = Command::new("git")
            .args([subcmd, "--stateless-rpc", "--advertise-refs"])
            .arg(&git_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| StoreError::Backend(format!("spawn git {subcmd}: {e}")))?;

        let (status, stdout, stderr) = run_bounded_git_child(&mut child, None, subcmd).await?;
        if !status.success() {
            return Err(StoreError::Backend(format!(
                "git {subcmd} --advertise-refs failed: {}",
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        let mut resp = pkt_line_frame(format!("# service={service}\n").as_bytes());
        resp.extend_from_slice(b"0000");
        resp.extend_from_slice(&stdout);
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
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| StoreError::Backend(format!("spawn git {subcmd}: {e}")))?;

        let (status, stdout, stderr) =
            run_bounded_git_child(&mut child, Some(body), subcmd).await?;
        if !status.success() {
            return Err(StoreError::Backend(format!(
                "git {subcmd} --stateless-rpc failed: {}",
                String::from_utf8_lossy(&stderr).trim()
            )));
        }

        if service == "git-receive-pack" {
            self.import_git_refs_into_jj(repo_root).await?;
        }
        let content_type = format!("application/x-{service}-result");
        Ok((content_type, stdout))
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

async fn run_bounded_git_child(
    child: &mut tokio::process::Child,
    stdin_body: Option<&[u8]>,
    subcmd: &str,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), StoreError> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| StoreError::Backend(format!("git {subcmd} missing stdout pipe")))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| StoreError::Backend(format!("git {subcmd} missing stderr pipe")))?;
    let stdin_opt = child.stdin.take();

    let work = async {
        let write_fut = async move {
            if let Some(mut stdin) = stdin_opt {
                if let Some(body) = stdin_body {
                    stdin
                        .write_all(body)
                        .await
                        .map_err(|e| StoreError::Backend(format!("write git stdin: {e}")))?;
                }
                stdin
                    .shutdown()
                    .await
                    .map_err(|e| StoreError::Backend(format!("close git stdin: {e}")))?;
            }
            Ok::<(), StoreError>(())
        };
        let out_fut = async move {
            let mut out = Vec::new();
            let mut limited = (&mut stdout).take((MAX_GIT_OUTPUT_BYTES as u64) + 1);
            limited
                .read_to_end(&mut out)
                .await
                .map_err(|e| StoreError::Backend(format!("read git {subcmd} stdout: {e}")))?;
            if out.len() > MAX_GIT_OUTPUT_BYTES {
                return Err(StoreError::InvalidInput(format!(
                    "git {subcmd} output exceeded {MAX_GIT_OUTPUT_BYTES} bytes"
                )));
            }
            Ok(out)
        };
        let err_fut = async move {
            let mut err_buf = Vec::new();
            let mut limited = (&mut stderr).take(MAX_GIT_STDERR_BYTES as u64);
            let _ = limited.read_to_end(&mut err_buf).await;
            Ok::<Vec<u8>, StoreError>(err_buf)
        };
        let (_, out, err_buf) = tokio::try_join!(write_fut, out_fut, err_fut)?;
        let status = child
            .wait()
            .await
            .map_err(|e| StoreError::Backend(format!("wait git {subcmd}: {e}")))?;
        Ok((status, out, err_buf))
    };

    match tokio::time::timeout(GIT_CMD_TIMEOUT, work).await {
        Ok(res) => res,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(StoreError::Backend(format!("git {subcmd} timed out")))
        }
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
