//! Synchronous SQLite Decision Log storage, atomic idempotent append, and MMR proof queries.

use crate::mmr_store::{append_mmr_in_tx, query_inclusion_proof_sync};
use crate::schema::{blob_to_digest, json_err, sqlite_err};
use hephaestus_core::{
    ChangeId, DecisionDraft, DecisionRecord, DecisionStatus, GENESIS_HASH, IdempotencyKey,
    MmrProof, OpId, RepoId, StreamKind, compute_decision_hash, verify_decision_chain,
};
use hephaestus_store::StoreError;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

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

type DecisionRow = (
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

pub(crate) fn list_decisions_sync(
    conn: &Connection,
    repo_id: &RepoId,
    change_id: Option<&ChangeId>,
) -> Result<Vec<DecisionRecord>, StoreError> {
    let sql = if change_id.is_some() {
        "SELECT seq, decision_id, prev_hash, record_hash, mmr_root, change_id, op_id, author,
                status, rationale, alternatives_json, supersedes, recorded_at_ms
         FROM decisions WHERE repo_id = ?1 AND change_id = ?2 ORDER BY seq ASC"
    } else {
        "SELECT seq, decision_id, prev_hash, record_hash, mmr_root, change_id, op_id, author,
                status, rationale, alternatives_json, supersedes, recorded_at_ms
         FROM decisions WHERE repo_id = ?1 ORDER BY seq ASC"
    };
    let mut stmt = conn.prepare(sql).map_err(sqlite_err)?;
    let parse_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<DecisionRow> {
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
    };
    let rows = if let Some(ch) = change_id {
        stmt.query_map(params![repo_id.as_str(), ch.as_str()], parse_row)
    } else {
        stmt.query_map(params![repo_id.as_str()], parse_row)
    }
    .map_err(sqlite_err)?;

    let mut out = Vec::new();
    for row in rows {
        let (seq, decision_id, prev, rec_h, mmr_h, ch, op, author, status_s, rat, alts, sup, ts) =
            row.map_err(sqlite_err)?;
        let status = DecisionStatus::parse(&status_s)
            .ok_or_else(|| StoreError::Backend(format!("unknown decision status `{status_s}`")))?;
        let alternatives: Vec<String> = serde_json::from_str(&alts).map_err(json_err)?;
        out.push(DecisionRecord {
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
        });
    }
    Ok(out)
}

pub(crate) fn verify_decisions_sync(
    conn: &Connection,
    repo_id: &RepoId,
) -> Result<u64, StoreError> {
    let records = list_decisions_sync(conn, repo_id, None)?;
    verify_decision_chain(&records)?;
    Ok(records.len() as u64)
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
