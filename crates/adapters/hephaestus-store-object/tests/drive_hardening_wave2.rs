#![forbid(unsafe_code)]
//! Hardened Google Drive tests: 256 KiB-aligned chunked `308 Resume Incomplete` uploads,
//! `Retry-After` on 503, retryable vs permanent 403, OAuth refresh, and paginated `list_bundles`.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use hephaestus_core::{DRIVE_FILE_SCOPE, DriveOAuthFsm, MonoTime, SecretString};
use hephaestus_store::{ObjectBackend, StoreError};
use hephaestus_store_object::{DRIVE_CHUNK_ALIGNMENT, DriveHttpClient, GoogleDriveStore};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[derive(Deserialize)]
struct ListQuery {
    #[serde(rename = "pageToken")]
    page_token: Option<String>,
}

struct HardenedMockDrive {
    sessions: Mutex<HashMap<String, Vec<u8>>>,
    files: Mutex<HashMap<String, (String, Vec<u8>)>>,
    chunks_received: AtomicUsize,
    refreshes: AtomicUsize,
    transient_403_left: AtomicUsize,
    transient_503_left: AtomicUsize,
}

fn prng_blob(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        out.push((s >> 33) as u8);
    }
    out
}

#[tokio::test]
async fn drive_chunked_308_oauth_refresh_retry_after_and_dr_list_pagination() {
    let st = Arc::new(HardenedMockDrive {
        sessions: Mutex::new(HashMap::new()),
        files: Mutex::new(HashMap::new()),
        chunks_received: AtomicUsize::new(0),
        refreshes: AtomicUsize::new(0),
        transient_403_left: AtomicUsize::new(1),
        transient_503_left: AtomicUsize::new(1),
    });

    let app = Router::new()
        .route(
            "/oauth/token",
            post(|State(s): State<Arc<HardenedMockDrive>>| async move {
                s.refreshes.fetch_add(1, Ordering::SeqCst);
                Json(json!({ "access_token": "fresh-tok", "expires_in": 3600 }))
            }),
        )
        .route(
            "/upload/drive/v3/files",
            post(|headers: HeaderMap, State(s): State<Arc<HardenedMockDrive>>| async move {
                if headers.get("authorization").and_then(|v| v.to_str().ok())
                    != Some("Bearer fresh-tok")
                {
                    return (StatusCode::UNAUTHORIZED, HeaderMap::new(), "expired".to_owned());
                }
                if s.transient_503_left
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                    .is_ok()
                {
                    let mut h = HeaderMap::new();
                    h.insert("retry-after", "1".parse().unwrap());
                    return (StatusCode::SERVICE_UNAVAILABLE, h, "busy".to_owned());
                }
                if s.transient_403_left
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                    .is_ok()
                {
                    return (
                        StatusCode::FORBIDDEN,
                        HeaderMap::new(),
                        r#"{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}"#.to_owned(),
                    );
                }
                let mut h = HeaderMap::new();
                h.insert("location", "/upload/sess/1".parse().unwrap());
                (StatusCode::OK, h, String::new())
            }),
        )
        .route(
            "/upload/sess/{sid}",
            put(
                |Path(sid): Path<String>,
                 headers: HeaderMap,
                 State(s): State<Arc<HardenedMockDrive>>,
                 body: Bytes| async move {
                    s.chunks_received.fetch_add(1, Ordering::SeqCst);
                    let cr = headers.get("content-range").unwrap().to_str().unwrap();
                    let (span, total_s) = cr.strip_prefix("bytes ").unwrap().split_once('/').unwrap();
                    let (start_s, end_s) = span.split_once('-').unwrap();
                    let (start, end, total): (usize, usize, usize) = (
                        start_s.parse().unwrap(),
                        end_s.parse().unwrap(),
                        total_s.parse().unwrap(),
                    );
                    let mut guard = s.sessions.lock().unwrap();
                    let buf = guard.entry(sid).or_default();
                    if buf.len() < end + 1 {
                        buf.resize(end + 1, 0);
                    }
                    buf[start..=end].copy_from_slice(&body);
                    if end + 1 < total {
                        let mut h = HeaderMap::new();
                        h.insert("range", format!("bytes=0-{end}").parse().unwrap());
                        return (StatusCode::PERMANENT_REDIRECT, h, String::new());
                    }
                    let finished = buf.clone();
                    s.files
                        .lock()
                        .unwrap()
                        .insert("fid-chunked".into(), ("b1.grnb.zst".into(), finished));
                    (
                        StatusCode::OK,
                        HeaderMap::new(),
                        r#"{"id":"fid-chunked"}"#.to_owned(),
                    )
                },
            ),
        )
        .route(
            "/drive/v3/files",
            get(|Query(q): Query<ListQuery>| async move {
                if q.page_token.as_deref() == Some("p2") {
                    Json(json!({ "files": [{"id": "fid-2", "name": "b2.grnb.zst", "size": "2048"}] }))
                } else {
                    Json(json!({
                        "nextPageToken": "p2",
                        "files": [{"id": "fid-chunked", "name": "b1.grnb.zst", "size": "1024"}]
                    }))
                }
            }),
        )
        .route(
            "/drive/v3/files/perm-denied",
            get(|| async {
                (
                    StatusCode::FORBIDDEN,
                    r#"{"error":{"errors":[{"reason":"insufficientPermissions"}]}}"#,
                )
            }),
        )
        .with_state(Arc::clone(&st));

    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://[{}]:{}", addr.ip(), addr.port());

    let mut fsm = DriveOAuthFsm::new("cid", "http://[::1]:0/cb", DRIVE_FILE_SCOPE).unwrap();
    fsm.apply_token_response(
        SecretString::new("stale-tok"),
        Some(SecretString::new("refresh-tok")),
        10,
        MonoTime(0),
    );
    let client = DriveHttpClient::with_oauth_fsm(
        &base,
        Arc::new(RwLock::new(fsm)),
        Some(format!("{base}/oauth/token")),
    )
    .unwrap()
    .with_upload_chunk_bytes(DRIVE_CHUNK_ALIGNMENT);
    let drive = GoogleDriveStore::new(client, 9).with_fast_test_retries();

    let payload = prng_blob(600 * 1024, 555);
    let uploaded = drive
        .put_bundle("b1.grnb.zst", payload.clone())
        .await
        .unwrap();
    assert_eq!(uploaded.object_id, "fid-chunked");
    assert_eq!(st.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(st.chunks_received.load(Ordering::SeqCst), 3);
    assert_eq!(
        st.files.lock().unwrap().get("fid-chunked").unwrap().1,
        payload
    );

    let perm_err = drive.get_bundle("perm-denied").await.unwrap_err();
    assert!(matches!(perm_err, StoreError::Backend(_)));

    let listed = drive.list_bundles().await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].object_id, "fid-chunked");
    assert_eq!(listed[1].object_id, "fid-2");
}
