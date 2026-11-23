//! Synchronous SQLite Orthogonal Observation Log storage, SQL predicate pushdown, and MMR proofs.

use crate::log_rows::{decode_observation_row, parse_observation_row};
use crate::mmr_store::{append_mmr_in_tx, query_inclusion_proof_sync};
use crate::schema::{blob_to_digest, json_err, sqlite_err};
use hephaestus_core::{
    DEFAULT_LOG_PAGE_LIMIT, GENESIS_HASH, IdempotencyKey, MAX_LOG_PAGE_LIMIT, MmrProof,
    ObservationChainVerifier, ObservationDraft, ObservationFilter, ObservationRecord, RepoId,
    StreamKind, canonicalize_json, compute_observation_hash,
};
use hephaestus_store::StoreError;
use rusqlite::types::Value as SqlValue;
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter,
};

fn insert_observation_in_tx(
    tx: &Transaction<'_>,
    repo_id: &RepoId,
    draft: ObservationDraft,
) -> Result<ObservationRecord, StoreError> {
    if draft.observation_id.trim().is_empty()
        || draft.producer.trim().is_empty()
        || draft.summary.trim().is_empty()
        || draft.metadata_json.trim().is_empty()
    {
        return Err(StoreError::InvalidInput(
            "observation_id, producer, summary, and metadata_json must not be empty".into(),
        ));
    }
    canonicalize_json(&draft.metadata_json)
        .map_err(|e| StoreError::InvalidInput(format!("invalid metadata_json: {e}")))?;

    let dup: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM observations WHERE repo_id = ?1 AND observation_id = ?2 LIMIT 1",
            params![repo_id.as_str(), draft.observation_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_err)?;
    if dup.is_some() {
        return Err(StoreError::Conflict(format!(
            "observation `{}` already exists in repo `{}`",
            draft.observation_id, repo_id
        )));
    }
    let head: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT seq, record_hash FROM observations
             WHERE repo_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![repo_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sqlite_err)?;
    let (seq, prev_hash) = match head {
        Some((last_seq, raw_hash)) => (
            (last_seq as u64).saturating_add(1),
            blob_to_digest(&raw_hash, "observations.record_hash")?,
        ),
        None => (0, GENESIS_HASH),
    };
    let record_hash = compute_observation_hash(seq, prev_hash, &draft);
    let mmr_root = append_mmr_in_tx(tx, repo_id, StreamKind::Observation, seq, record_hash)?;
    let passed_i64 = draft.passed.map(i64::from);

    tx.execute(
        "INSERT INTO observations
         (repo_id, seq, observation_id, prev_hash, record_hash, mmr_root, kind, change_id, commit_id,
          op_id, producer, passed, summary, payload_digest, custody_uri, metadata_json, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            repo_id.as_str(),
            seq as i64,
            draft.observation_id,
            prev_hash.as_bytes().as_slice(),
            record_hash.as_bytes().as_slice(),
            mmr_root.as_bytes().as_slice(),
            draft.kind.as_str(),
            draft.change_id.as_str(),
            draft.commit_id.as_str(),
            draft.op_id.as_str(),
            draft.producer,
            passed_i64,
            draft.summary,
            draft.payload_digest.as_bytes().as_slice(),
            draft.custody_uri,
            draft.metadata_json,
            draft.recorded_at_ms as i64,
        ],
    )
    .map_err(sqlite_err)?;

    Ok(ObservationRecord {
        seq,
        prev_hash,
        record_hash,
        mmr_root,
        observation_id: draft.observation_id,
        kind: draft.kind,
        change_id: draft.change_id,
        commit_id: draft.commit_id,
        op_id: draft.op_id,
        producer: draft.producer,
        passed: draft.passed,
        summary: draft.summary,
        payload_digest: draft.payload_digest,
        custody_uri: draft.custody_uri,
        metadata_json: draft.metadata_json,
        recorded_at_ms: draft.recorded_at_ms,
    })
}

pub(crate) fn append_observation_sync(
    conn: &mut Connection,
    repo_id: &RepoId,
    draft: ObservationDraft,
) -> Result<ObservationRecord, StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_err)?;
    let rec = insert_observation_in_tx(&tx, repo_id, draft)?;
    tx.commit().map_err(sqlite_err)?;
    Ok(rec)
}

/// Atomically checks idempotency, inserts the Observation record + MMR nodes, and records
/// the idempotency receipt inside a single `BEGIN IMMEDIATE` transaction.
pub(crate) fn append_observation_idempotent_sync(
    conn: &mut Connection,
    repo_id: &RepoId,
    draft: ObservationDraft,
    key: &IdempotencyKey,
    now_ms: u64,
) -> Result<(ObservationRecord, bool), StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_err)?;
    let existing: Option<Vec<u8>> = tx
        .query_row(
            "SELECT ack_payload FROM idempotency_ledger
             WHERE repo_id = ?1 AND stream_kind = ?2 AND blake3_digest = ?3",
            params![
                key.repo_id.as_str(),
                key.stream_kind.as_str(),
                key.digest.as_bytes().as_slice(),
            ],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_err)?;
    if let Some(prev) = existing {
        tx.commit().map_err(sqlite_err)?;
        let rec: ObservationRecord = serde_json::from_slice(&prev).map_err(json_err)?;
        return Ok((rec, true));
    }
    let rec = insert_observation_in_tx(&tx, repo_id, draft)?;
    let ack = serde_json::to_vec(&rec).map_err(json_err)?;
    tx.execute(
        "INSERT INTO idempotency_ledger
         (repo_id, stream_kind, blake3_digest, ack_payload, created_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key.repo_id.as_str(),
            key.stream_kind.as_str(),
            key.digest.as_bytes().as_slice(),
            ack,
            now_ms as i64,
        ],
    )
    .map_err(sqlite_err)?;
    tx.commit().map_err(sqlite_err)?;
    Ok((rec, false))
}

/// Pushes all [`ObservationFilter`] predicates directly into parameterized SQL leveraging
/// `idx_observations_change`, `idx_observations_commit`, and `idx_observations_kind`,
/// always enforcing a bounded page `LIMIT`.
pub(crate) fn query_observations_sync(
    conn: &Connection,
    repo_id: &RepoId,
    filter: &ObservationFilter,
) -> Result<Vec<ObservationRecord>, StoreError> {
    let mut sql = String::from(
        "SELECT seq, observation_id, prev_hash, record_hash, mmr_root, kind, change_id, commit_id,
                op_id, producer, passed, summary, payload_digest, custody_uri, metadata_json, recorded_at_ms
         FROM observations WHERE repo_id = ?",
    );
    let mut bind: Vec<SqlValue> = vec![SqlValue::Text(repo_id.as_str().to_owned())];
    if let Some(ch) = &filter.change_id {
        sql.push_str(" AND change_id = ?");
        bind.push(SqlValue::Text(ch.as_str().to_owned()));
    }
    if let Some(cm) = &filter.commit_id {
        sql.push_str(" AND commit_id = ?");
        bind.push(SqlValue::Text(cm.as_str().to_owned()));
    }
    if let Some(op) = &filter.op_id {
        sql.push_str(" AND op_id = ?");
        bind.push(SqlValue::Text(op.as_str().to_owned()));
    }
    if let Some(kind) = filter.kind {
        sql.push_str(" AND kind = ?");
        bind.push(SqlValue::Text(kind.as_str().to_owned()));
    }
    if let Some(passed) = filter.passed {
        sql.push_str(" AND passed = ?");
        bind.push(SqlValue::Integer(i64::from(passed)));
    }
    if let Some(since_seq) = filter.since_seq {
        sql.push_str(" AND seq >= ?");
        bind.push(SqlValue::Integer(since_seq as i64));
    }
    let effective_limit = filter
        .limit
        .unwrap_or(DEFAULT_LOG_PAGE_LIMIT)
        .min(MAX_LOG_PAGE_LIMIT);
    sql.push_str(" ORDER BY seq ASC LIMIT ?");
    bind.push(SqlValue::Integer(effective_limit as i64));

    let mut stmt = conn.prepare(&sql).map_err(sqlite_err)?;
    let rows = stmt
        .query_map(params_from_iter(bind), parse_observation_row)
        .map_err(sqlite_err)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(decode_observation_row(row.map_err(sqlite_err)?)?);
    }
    Ok(out)
}

pub(crate) fn verify_observations_sync(
    conn: &Connection,
    repo_id: &RepoId,
) -> Result<u64, StoreError> {
    let tx = conn.unchecked_transaction().map_err(sqlite_err)?;
    let (total_count, distinct_ids): (i64, i64) = tx
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT observation_id) FROM observations WHERE repo_id = ?1",
            params![repo_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sqlite_err)?;
    if total_count != distinct_ids {
        return Err(StoreError::ChainViolation(
            hephaestus_core::ChainError::DuplicateId {
                id: "duplicate observation_id in repository".into(),
            },
        ));
    }
    let mut verifier = ObservationChainVerifier::new();
    {
        let mut stmt = tx
            .prepare(
                "SELECT seq, observation_id, prev_hash, record_hash, mmr_root, kind, change_id, commit_id,
                        op_id, producer, passed, summary, payload_digest, custody_uri, metadata_json, recorded_at_ms
                 FROM observations WHERE repo_id = ?1 ORDER BY seq ASC",
            )
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map(params![repo_id.as_str()], parse_observation_row)
            .map_err(sqlite_err)?;
        for row in rows {
            let rec = decode_observation_row(row.map_err(sqlite_err)?)?;
            verifier.step_with_options(&rec, false)?;
        }
    }
    Ok(verifier.verified_count())
}

pub(crate) fn observation_inclusion_proof_sync(
    conn: &Connection,
    repo_id: &RepoId,
    seq: u64,
) -> Result<MmrProof, StoreError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM observations WHERE repo_id = ?1",
            params![repo_id.as_str()],
            |r| r.get(0),
        )
        .map_err(sqlite_err)?;
    query_inclusion_proof_sync(conn, repo_id, StreamKind::Observation, seq, count as u64)
}
