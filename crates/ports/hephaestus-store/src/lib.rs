#![forbid(unsafe_code)]
//! Driven port contracts and shared storage/replication DTOs for Hephaestus.

pub mod ports;
pub mod types;

pub use bytes::Bytes;
pub use ports::{CatalogStore, LogStore, ObjectBackend, WebhookSink};
pub use types::{
    BlobLocation, BoxFuture, CatalogStats, CommitRef, IdempotentReceipt, ObjectMeta, ObjectRef,
    PushWebhookEvent, SnapshotMetadata, StoreError,
};
