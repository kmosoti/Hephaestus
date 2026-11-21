//! Synchronous SQLite catalog, idempotency ledger, and bookmark ref operations.

use crate::schema::sqlite_err;
use hephaestus_core::{BlobDigest, ChangeId, CommitId, IdempotencyKey, OpId, RepoId, SealedBundle};
use hephaestus_store::{BlobLocation, CatalogStats, CommitRef, IdempotentReceipt, StoreError};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

pub(crate) fn put_inline_sync(
    conn: &Connection,
    digest: &BlobDigest,
    data: &[u8],
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR IGNORE INTO inline_blobs (blake3_hash, data) VALUES (?1, ?2)",
        params![digest.as_bytes().as_slice(), data],
    )
    .map_err(sqlite_err)?;
    Ok(())
}

pub(crate) fn contains_sync(conn: &Connection, digest: &BlobDigest) -> Result<bool, StoreError> {
    let inline: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM inline_blobs WHERE blake3_hash = ?1 LIMIT 1",
            params![digest.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_err)?;
    if inline.is_some() {
        return Ok(true);
    }
    let packed: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM packed_objects WHERE blake3_hash = ?1 LIMIT 1",
            params![digest.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_err)?;
    Ok(packed.is_some())
}

pub(crate) fn lookup_sync(
    conn: &Connection,
    digest: &BlobDigest,
) -> Result<Option<BlobLocation>, StoreError> {
    let inline: Option<Vec<u8>> = conn
        .query_row(
            "SELECT data FROM inline_blobs WHERE blake3_hash = ?1",
            params![digest.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_err)?;
    if let Some(bytes) = inline {
        return Ok(Some(BlobLocation::Inline(bytes)));
    }
    let packed: Option<(String, String, i64, i64)> = conn
        .query_row(
            "SELECT object_id, bundle_id, byte_offset, byte_len
             FROM packed_objects WHERE blake3_hash = ?1",
            params![digest.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(sqlite_err)?;
    Ok(
        packed.map(|(object_id, bundle_id, off, len)| BlobLocation::Packed {
            object_id,
            bundle_id,
            byte_offset: off as u64,
            byte_len: len as u32,
        }),
    )
}

pub(crate) fn record_bundle_sync(
    conn: &mut Connection,
    bundle: &SealedBundle,
    object_id: &str,
) -> Result<(), StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_err)?;
    let comp_len = if bundle.compressed_bytes.is_empty() {
        bundle.raw_bytes_len as i64
    } else {
        bundle.compressed_bytes.len() as i64
    };
    tx.execute(
        "INSERT OR REPLACE INTO bundles (bundle_id, object_id, compressed_bytes, entry_count)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            bundle.bundle_id,
            object_id,
            comp_len,
            bundle.entries.len() as i64,
        ],
    )
    .map_err(sqlite_err)?;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO packed_objects
                 (blake3_hash, object_id, bundle_id, byte_offset, byte_len)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .map_err(sqlite_err)?;
        for entry in &bundle.entries {
            stmt.execute(params![
                entry.blake3_hash.as_slice(),
                object_id,
                bundle.bundle_id,
                entry.byte_offset as i64,
                i64::from(entry.byte_len),
            ])
            .map_err(sqlite_err)?;
        }
    }
    tx.commit().map_err(sqlite_err)?;
    Ok(())
}

pub(crate) fn check_idempotent_sync(
    conn: &Connection,
    key: &IdempotencyKey,
) -> Result<Option<Vec<u8>>, StoreError> {
    conn.query_row(
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
    .map_err(sqlite_err)
}

pub(crate) fn record_idempotent_sync(
    conn: &mut Connection,
    key: &IdempotencyKey,
    ack_payload: &[u8],
    now_ms: u64,
) -> Result<IdempotentReceipt, StoreError> {
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
        return Ok(IdempotentReceipt {
            already_applied: true,
            ack_payload: prev,
        });
    }
    tx.execute(
        "INSERT INTO idempotency_ledger
         (repo_id, stream_kind, blake3_digest, ack_payload, created_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key.repo_id.as_str(),
            key.stream_kind.as_str(),
            key.digest.as_bytes().as_slice(),
            ack_payload,
            now_ms as i64,
        ],
    )
    .map_err(sqlite_err)?;
    tx.commit().map_err(sqlite_err)?;
    Ok(IdempotentReceipt {
        already_applied: false,
        ack_payload: ack_payload.to_vec(),
    })
}

pub(crate) fn upsert_ref_sync(conn: &Connection, commit_ref: &CommitRef) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR REPLACE INTO refs
         (repo_id, bookmark, change_id, commit_id, op_id, tree_blob_hash, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            commit_ref.repo_id.as_str(),
            commit_ref.bookmark,
            commit_ref.change_id.as_str(),
            commit_ref.commit_id.as_str(),
            commit_ref.op_id.as_str(),
            commit_ref.tree_blob_hash,
            commit_ref.updated_ms as i64,
        ],
    )
    .map_err(sqlite_err)?;
    Ok(())
}

/// Atomically checks idempotency, upserts `commit_ref`, and records `ack_payload`
/// inside a single `BEGIN IMMEDIATE` transaction.
pub(crate) fn upsert_ref_idempotent_sync(
    conn: &mut Connection,
    commit_ref: &CommitRef,
    key: &IdempotencyKey,
    ack_payload: &[u8],
    now_ms: u64,
) -> Result<IdempotentReceipt, StoreError> {
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
        return Ok(IdempotentReceipt {
            already_applied: true,
            ack_payload: prev,
        });
    }
    upsert_ref_sync(&tx, commit_ref)?;
    tx.execute(
        "INSERT INTO idempotency_ledger
         (repo_id, stream_kind, blake3_digest, ack_payload, created_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key.repo_id.as_str(),
            key.stream_kind.as_str(),
            key.digest.as_bytes().as_slice(),
            ack_payload,
            now_ms as i64,
        ],
    )
    .map_err(sqlite_err)?;
    tx.commit().map_err(sqlite_err)?;
    Ok(IdempotentReceipt {
        already_applied: false,
        ack_payload: ack_payload.to_vec(),
    })
}

pub(crate) fn list_refs_sync(
    conn: &Connection,
    repo_id: &RepoId,
) -> Result<Vec<CommitRef>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT repo_id, bookmark, change_id, commit_id, op_id, tree_blob_hash, updated_ms
             FROM refs WHERE repo_id = ?1 ORDER BY bookmark ASC",
        )
        .map_err(sqlite_err)?;
    let rows = stmt
        .query_map(params![repo_id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })
        .map_err(sqlite_err)?;
    let mut out = Vec::new();
    for row in rows {
        let (repo, bookmark, ch, cm, op, tree, updated) = row.map_err(sqlite_err)?;
        out.push(CommitRef {
            repo_id: RepoId::parse(&repo)?,
            bookmark,
            change_id: ChangeId::parse(&ch)?,
            commit_id: CommitId::parse(&cm)?,
            op_id: OpId::parse(&op)?,
            tree_blob_hash: tree,
            updated_ms: updated as u64,
        });
    }
    Ok(out)
}

pub(crate) fn stats_sync(conn: &Connection) -> Result<CatalogStats, StoreError> {
    let count = |table: &str| -> Result<u64, StoreError> {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let n: i64 = conn.query_row(&sql, [], |r| r.get(0)).map_err(sqlite_err)?;
        Ok(n as u64)
    };
    Ok(CatalogStats {
        inline_count: count("inline_blobs")?,
        packed_count: count("packed_objects")?,
        bundle_count: count("bundles")?,
        idempotency_count: count("idempotency_ledger")?,
        decision_count: count("decisions")?,
        observation_count: count("observations")?,
    })
}

pub(crate) fn checkpoint_wal_sync(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
        .map_err(sqlite_err)
}
