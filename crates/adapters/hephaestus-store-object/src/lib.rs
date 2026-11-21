#![forbid(unsafe_code)]
//! Object storage adapters (`object_store` + native-IPv6 Google Drive), packed CAS engine,
//! and outbound push webhook sink.

mod cas_engine;
mod drive_client;
mod drive_http;
mod drive_ops;
mod object_adapter;
mod webhook;

pub use cas_engine::PackedCasEngine;
pub use drive_client::GoogleDriveStore;
pub use drive_http::{
    DRIVE_CHUNK_ALIGNMENT, DRIVE_UPLOAD_CHUNK_BYTES, DriveHttpClient, GOOGLE_DRIVE_BASE_URL,
};
pub use drive_ops::{DriveBundleEntry, DriveHttpError};
pub use object_adapter::{ObjectStoreBackend, ObjectStoreConfig};
pub use webhook::{HttpWebhookSink, NoopWebhookSink};
