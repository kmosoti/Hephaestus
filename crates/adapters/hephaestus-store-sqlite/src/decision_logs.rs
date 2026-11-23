//! Synchronous SQLite Decision Log storage, atomic idempotent append, and MMR proof queries.

use crate::log_rows::{decode_decision_row, parse_decision_row};
use crate::mmr_store::{append_mmr_in_tx, query_inclusion_proof_sync};
use crate::schema::{blob_to_digest, json_err, sqlite_err};
use hephaestus_core::{
    ChangeId, DEFAULT_LOG_PAGE_LIMIT, DecisionChainVerifier, DecisionDraft, DecisionRecord,
    GENESIS_HASH, IdempotencyKey, MAX_LOG_PAGE_LIMIT, MmrProof, RepoId, StreamKind,
    compute_decision_hash,
};
use hephaestus_store::StoreError;
use rusqlite::types::Value as SqlValue;
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter,
};

fn insert_decision_in_tx(
    tx: &Transaction<'_>,
    repo_id: &RepoId,
    draft: DecisionDraft,
) -> Result<DecisionRecord, StoreError> {
    if draft.decision_id.trim().is_empty()
        || draft.author.trim().is_empty()
        || draft.rationale.trim().is_empty()
    {
        return Err(StoreError::InvalidInput(
            "decision_id, author, and rationale must not be empty".into(),
        ));
    }
    let dup: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM decisions WHERE repo_id = ?1 AND decision_id = ?2 LIMIT 1",
            params![repo_id.as_str(), draft.decision_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_err)?;
    if dup.is_some() {
        return Err(StoreError::Conflict(format!(
            "decision `{}` already exists in repo `{}`",
            draft.decision_id, repo_id
        )));
    }
    if let Some(target) = &draft.supersedes {
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM decisions WHERE repo_id = ?1 AND decision_id = ?2 LIMIT 1",
                params![repo_id.as_str(), target],
                |r| r.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;
        if exists.is_none() {
            return Err(StoreError::InvalidInput(format!(
                "supersedes target `{target}` not found in repo `{repo_id}`"
            )));
        }
    }

    let head: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT seq, record_hash FROM decisions
             WHERE repo_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![repo_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sqlite_err)?;

    let (seq, prev_hash) = match head {
        Some((last_seq, raw_hash)) => (
            (last_seq as u64).saturating_add(1),
            blob_to_digest(&raw_hash, "decisions.record_hash")?,
        ),
        None => (0, GENESIS_HASH),
    };
    let record_hash = compute_decision_hash(seq, prev_hash, &draft);
    let mmr_root = append_mmr_in_tx(tx, repo_id, StreamKind::Decision, seq, record_hash)?;
    let alternatives_json = serde_json::to_string(&draft.alternatives).map_err(json_err)?;

    tx.execute(
        "INSERT INTO decisions
         (repo_id, seq, decision_id, prev_hash, record_hash, mmr_root, change_id, op_id, author,
          status, rationale, alternatives_json, supersedes, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            repo_id.as_str(),
            seq as i64,
            draft.decision_id,
            prev_hash.as_bytes().as_slice(),
            record_hash.as_bytes().as_slice(),
            mmr_root.as_bytes().as_slice(),
            draft.change_id.as_str(),
            draft.op_id.as_str(),
            draft.author,
            draft.status.as_str(),
            draft.rationale,
            alternatives_json,
            draft.supersedes,
            draft.recorded_at_ms as i64,
        ],
    )
    .map_err(sqlite_err)?;

    Ok(DecisionRecord {
        seq,
        prev_hash,
        record_hash,
        mmr_root,
        decision_id: draft.decision_id,
        change_id: draft.change_id,
        op_id: draft.op_id,
        author: draft.author,
        status: draft.status,
        rationale: draft.rationale,
        alternatives: draft.alternatives,
        supersedes: draft.supersedes,
        recorded_at_ms: draft.recorded_at_ms,
    })
}

pub(crate) fn append_decision_sync(
    conn: &mut Connection,
    repo_id: &RepoId,
    draft: DecisionDraft,
) -> Result<DecisionRecord, StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_err)?;
    let rec = insert_decision_in_tx(&tx, repo_id, draft)?;
    tx.commit().map_err(sqlite_err)?;
    Ok(rec)
}

/// Atomically checks idempotency, inserts the Decision record + MMR nodes, and records the
/// idempotency receipt inside a single `BEGIN IMMEDIATE` transaction.
pub(crate) fn append_decision_idempotent_sync(
    conn: &mut Connection,
    repo_id: &RepoId,
    draft: DecisionDraft,
    key: &IdempotencyKey,
    now_ms: u64,
) -> Result<(DecisionRecord, bool), StoreError> {
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
        let rec: DecisionRecord = serde_json::from_slice(&prev).map_err(json_err)?;
        return Ok((rec, true));
    }
    let rec = insert_decision_in_tx(&tx, repo_id, draft)?;
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

pub(crate) fn query_decisions_sync(
    conn: &Connection,
    repo_id: &RepoId,
    change_id: Option<&ChangeId>,
    since_seq: Option<u64>,
    limit: Option<usize>,
) -> Result<Vec<DecisionRecord>, StoreError> {
    let effective_limit = limit
        .unwrap_or(DEFAULT_LOG_PAGE_LIMIT)
        .min(MAX_LOG_PAGE_LIMIT);
    let mut sql = String::from(
        "SELECT seq, decision_id, prev_hash, record_hash, mmr_root, change_id, op_id, author,
                status, rationale, alternatives_json, supersedes, recorded_at_ms
         FROM decisions WHERE repo_id = ?",
    );
    let mut bind: Vec<SqlValue> = vec![SqlValue::Text(repo_id.as_str().to_owned())];
    if let Some(ch) = change_id {
        sql.push_str(" AND change_id = ?");
        bind.push(SqlValue::Text(ch.as_str().to_owned()));
    }
    if let Some(seq) = since_seq {
        sql.push_str(" AND seq >= ?");
        bind.push(SqlValue::Integer(seq as i64));
    }
    sql.push_str(" ORDER BY seq ASC LIMIT ?");
    bind.push(SqlValue::Integer(effective_limit as i64));

    let mut stmt = conn.prepare(&sql).map_err(sqlite_err)?;
    let rows = stmt
        .query_map(params_from_iter(bind), parse_decision_row)
        .map_err(sqlite_err)?;

    let mut out = Vec::new();
    for row in rows {
        out.push(decode_decision_row(row.map_err(sqlite_err)?)?);
    }
    Ok(out)
}

pub(crate) fn verify_decisions_sync(
    conn: &Connection,
    repo_id: &RepoId,
) -> Result<u64, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT seq, decision_id, prev_hash, record_hash, mmr_root, change_id, op_id, author,
                    status, rationale, alternatives_json, supersedes, recorded_at_ms
             FROM decisions WHERE repo_id = ?1 ORDER BY seq ASC",
        )
        .map_err(sqlite_err)?;
    let rows = stmt
        .query_map(params![repo_id.as_str()], parse_decision_row)
        .map_err(sqlite_err)?;
    let mut verifier = DecisionChainVerifier::new();
    for row in rows {
        let rec = decode_decision_row(row.map_err(sqlite_err)?)?;
        verifier.step(&rec)?;
    }
    Ok(verifier.verified_count())
}

pub(crate) fn decision_inclusion_proof_sync(
    conn: &Connection,
    repo_id: &RepoId,
    seq: u64,
) -> Result<MmrProof, StoreError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM decisions WHERE repo_id = ?1",
            params![repo_id.as_str()],
            |r| r.get(0),
        )
        .map_err(sqlite_err)?;
    query_inclusion_proof_sync(conn, repo_id, StreamKind::Decision, seq, count as u64)
}
