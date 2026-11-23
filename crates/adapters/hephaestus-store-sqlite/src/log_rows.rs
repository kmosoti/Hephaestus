//! Row decoding helpers for Decision and Observation SQLite log queries.

use crate::schema::blob_to_digest;
use hephaestus_core::{
    ChangeId, CommitId, DecisionRecord, DecisionStatus, ObservationKind, ObservationRecord, OpId,
};
use hephaestus_store::StoreError;

pub(crate) type ObservationRow = (
    i64,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    String,
    Vec<u8>,
    Option<String>,
    String,
    i64,
);

pub(crate) fn parse_observation_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ObservationRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
        r.get(15)?,
    ))
}

pub(crate) fn decode_observation_row(row: ObservationRow) -> Result<ObservationRecord, StoreError> {
    let (
        seq,
        obs_id,
        prev,
        rec_h,
        mmr_h,
        kind_s,
        ch,
        cm,
        op,
        prod,
        passed_opt,
        sum,
        dig,
        uri,
        meta,
        ts,
    ) = row;
    let kind = ObservationKind::parse(&kind_s)
        .ok_or_else(|| StoreError::Backend(format!("unknown observation kind `{kind_s}`")))?;
    Ok(ObservationRecord {
        seq: seq as u64,
        prev_hash: blob_to_digest(&prev, "observations.prev_hash")?,
        record_hash: blob_to_digest(&rec_h, "observations.record_hash")?,
        mmr_root: blob_to_digest(&mmr_h, "observations.mmr_root")?,
        observation_id: obs_id,
        kind,
        change_id: ChangeId::parse(&ch)?,
        commit_id: CommitId::parse(&cm)?,
        op_id: OpId::parse(&op)?,
        producer: prod,
        passed: passed_opt.map(|v| v != 0),
        summary: sum,
        payload_digest: blob_to_digest(&dig, "observations.payload_digest")?,
        custody_uri: uri,
        metadata_json: meta,
        recorded_at_ms: ts as u64,
    })
}

pub(crate) type DecisionRow = (
    i64,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
);

pub(crate) fn parse_decision_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<DecisionRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
    ))
}

pub(crate) fn decode_decision_row(row: DecisionRow) -> Result<DecisionRecord, StoreError> {
    let (seq, decision_id, prev, rec_h, mmr_h, ch, op, author, status_s, rat, alts, sup, ts) = row;
    let status = DecisionStatus::parse(&status_s)
        .ok_or_else(|| StoreError::Backend(format!("unknown decision status `{status_s}`")))?;
    let alternatives: Vec<String> = serde_json::from_str(&alts)
        .map_err(|e| StoreError::Serialization(format!("json error: {e}")))?;
    Ok(DecisionRecord {
        seq: seq as u64,
        prev_hash: blob_to_digest(&prev, "decisions.prev_hash")?,
        record_hash: blob_to_digest(&rec_h, "decisions.record_hash")?,
        mmr_root: blob_to_digest(&mmr_h, "decisions.mmr_root")?,
        decision_id,
        change_id: ChangeId::parse(&ch)?,
        op_id: OpId::parse(&op)?,
        author,
        status,
        rationale: rat,
        alternatives,
        supersedes: sup,
        recorded_at_ms: ts as u64,
    })
}
