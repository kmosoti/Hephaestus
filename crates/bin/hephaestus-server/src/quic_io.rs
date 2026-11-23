//! Bounded chunked QUIC stream framing with weighted memory admission and deadlines.

use crate::quic_proto::{
    DEFAULT_QUIC_STREAM_DEADLINE, MAX_QUIC_FRAME_BYTES, MAX_QUIC_HEADER_BYTES,
    QUIC_STREAM_CHUNK_BYTES, QuicRequest, QuicResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

const BUDGET_WAIT_TIMEOUT: Duration = Duration::from_millis(250);

/// Declares whether a decoded QUIC frame header permits a trailing binary payload section.
pub trait QuicMessageMeta {
    /// Returns `true` only for operations that legitimately carry binary payload bytes.
    fn expects_binary_payload(&self) -> bool;
}

impl QuicMessageMeta for QuicRequest {
    fn expects_binary_payload(&self) -> bool {
        matches!(self, Self::PutBlob { .. })
    }
}

impl QuicMessageMeta for QuicResponse {
    fn expects_binary_payload(&self) -> bool {
        matches!(self, Self::BlobGet { found: true, .. })
    }
}

/// Streams `[u32 header_len][header_json][u64 payload_len][chunked payload]` over a QUIC stream.
pub async fn write_stream_message<T: Serialize>(
    send: &mut quinn::SendStream,
    header: &T,
    payload: &[u8],
) -> Result<(), String> {
    let json_bytes = serde_json::to_vec(header).map_err(|e| format!("encode json: {e}"))?;
    if json_bytes.len() > MAX_QUIC_HEADER_BYTES {
        return Err(format!("QUIC header exceeds {MAX_QUIC_HEADER_BYTES} bytes"));
    }
    if payload.len() > MAX_QUIC_FRAME_BYTES {
        return Err(format!("QUIC payload exceeds {MAX_QUIC_FRAME_BYTES} bytes"));
    }
    send.write_all(&(json_bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|e| format!("quic write hdr_len: {e}"))?;
    send.write_all(&json_bytes)
        .await
        .map_err(|e| format!("quic write hdr: {e}"))?;
    send.write_all(&(payload.len() as u64).to_be_bytes())
        .await
        .map_err(|e| format!("quic write payload_len: {e}"))?;
    for chunk in payload.chunks(QUIC_STREAM_CHUNK_BYTES) {
        send.write_all(chunk)
            .await
            .map_err(|e| format!("quic write chunk: {e}"))?;
    }
    send.finish().map_err(|e| format!("quic finish: {e}"))
}

async fn read_exact_bounded(
    recv: &mut quinn::RecvStream,
    buf: &mut [u8],
    read_timeout: Duration,
    deadline: Instant,
) -> Result<(), String> {
    tokio::time::timeout_at(
        deadline,
        tokio::time::timeout(read_timeout, recv.read_exact(buf)),
    )
    .await
    .map_err(|_| "quic stream exceeded absolute deadline".to_owned())?
    .map_err(|_| "quic stream read timed out".to_owned())?
    .map_err(|e| format!("quic read_exact: {e}"))
}

/// Reads `[u32 header_len][header_json][u64 payload_len][chunked payload]` with per-chunk
/// timeouts and default absolute stream deadline.
pub async fn read_stream_message<T: for<'de> Deserialize<'de> + QuicMessageMeta>(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
) -> Result<(T, Vec<u8>), String> {
    let (hdr, payload, _) =
        read_stream_message_budgeted(recv, read_timeout, DEFAULT_QUIC_STREAM_DEADLINE, None)
            .await?;
    Ok((hdr, payload))
}

/// Reads a bounded QUIC stream message, validating `expects_binary_payload()`, enforcing
/// `stream_deadline`, acquiring `payload_len` permits from `byte_budget`, and growing the
/// payload buffer incrementally via fallible `try_reserve`.
pub async fn read_stream_message_budgeted<T: for<'de> Deserialize<'de> + QuicMessageMeta>(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
    stream_deadline: Duration,
    byte_budget: Option<&Arc<Semaphore>>,
) -> Result<(T, Vec<u8>, Option<OwnedSemaphorePermit>), String> {
    let deadline = Instant::now() + stream_deadline;
    let mut len_buf = [0u8; 4];
    read_exact_bounded(recv, &mut len_buf, read_timeout, deadline).await?;
    let hdr_len = u32::from_be_bytes(len_buf) as usize;
    if hdr_len == 0 || hdr_len > MAX_QUIC_HEADER_BYTES {
        return Err(format!("invalid QUIC header length {hdr_len}"));
    }
    let mut hdr_buf = Vec::new();
    hdr_buf
        .try_reserve_exact(hdr_len)
        .map_err(|_| "QUIC header allocation failed".to_owned())?;
    hdr_buf.resize(hdr_len, 0);
    read_exact_bounded(recv, &mut hdr_buf, read_timeout, deadline).await?;
    let header: T =
        serde_json::from_slice(&hdr_buf).map_err(|e| format!("decode QUIC json: {e}"))?;

    let mut pay_len_buf = [0u8; 8];
    read_exact_bounded(recv, &mut pay_len_buf, read_timeout, deadline).await?;
    let payload_len = usize::try_from(u64::from_be_bytes(pay_len_buf))
        .map_err(|_| "QUIC payload length overflow".to_owned())?;
    if payload_len > MAX_QUIC_FRAME_BYTES {
        return Err(format!("QUIC payload exceeds {MAX_QUIC_FRAME_BYTES} bytes"));
    }
    if payload_len > 0 && !header.expects_binary_payload() {
        return Err("unexpected binary payload for non-blob QUIC operation".to_owned());
    }

    let permit = if let Some(budget) = byte_budget
        && payload_len > 0
    {
        let weight =
            u32::try_from(payload_len).map_err(|_| "QUIC payload weight overflow".to_owned())?;
        let acq = tokio::time::timeout_at(
            deadline,
            tokio::time::timeout(
                BUDGET_WAIT_TIMEOUT,
                Arc::clone(budget).acquire_many_owned(weight),
            ),
        )
        .await
        .map_err(|_| "quic stream exceeded absolute deadline".to_owned())?
        .map_err(|_| "QUIC aggregate inflight byte budget exhausted".to_owned())?
        .map_err(|_| "QUIC byte budget semaphore closed".to_owned())?;
        Some(acq)
    } else {
        None
    };

    let mut payload = Vec::new();
    if payload_len > 0 {
        let mut scratch = vec![0u8; QUIC_STREAM_CHUNK_BYTES.min(payload_len)];
        let mut remaining = payload_len;
        while remaining > 0 {
            let step = remaining.min(QUIC_STREAM_CHUNK_BYTES);
            read_exact_bounded(recv, &mut scratch[..step], read_timeout, deadline).await?;
            payload
                .try_reserve(step)
                .map_err(|_| "QUIC payload allocation failed".to_owned())?;
            payload.extend_from_slice(&scratch[..step]);
            remaining -= step;
        }
    }
    Ok((header, payload, permit))
}
