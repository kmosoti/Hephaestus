#![forbid(unsafe_code)]
//! Authoritative Jujutsu (`jj-lib 0.47`) storage backend, OpLog/ChangeId indexer,
//! and Git smart-HTTP compatibility bridge.

mod backend;
mod cas_codec;
mod cas_driver;
mod git_bridge;
mod repo_index;
mod repo_ops;

pub use backend::{
    HephaestusBackend, hephaestus_store_factories, hephaestus_store_factories_with_cas,
};
pub use cas_codec::CasFileManifest;
pub use git_bridge::{GitSmartHttpBridge, pkt_line_frame};
pub use repo_index::JjOpSummary;
pub use repo_ops::{JjCommitInput, JjCommitResult, JjRepoService, default_user_settings};
