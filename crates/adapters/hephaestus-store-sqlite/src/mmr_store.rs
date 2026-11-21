//! Persistent SQLite MMR node storage enabling `O(log N)` append and inclusion proofs.

use crate::schema::{blob_to_digest, sqlite_err};
use hephaestus_core::{
    BlobDigest, MmrProof, MmrSibling, RepoId, StreamKind, bag_mmr_peaks, compute_append_nodes,
    peak_positions, proof_node_positions,
};
use hephaestus_store::StoreError;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

fn fetch_node(
    conn: &Connection,
    repo_id: &RepoId,
    stream: StreamKind,
    pos: u64,
) -> Result<BlobDigest, StoreError> {
    let raw: Option<Vec<u8>> = conn
        .query_row(
            "SELECT node_hash FROM mmr_nodes
             WHERE repo_id = ?1 AND stream_kind = ?2 AND pos = ?3",
            params![repo_id.as_str(), stream.as_str(), pos as i64],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_err)?;
    let bytes = raw.ok_or_else(|| {
        StoreError::NotFound(format!(
            "missing mmr node pos {pos} for {} ({})",
            repo_id,
            stream.as_str()
        ))
    })?;
    blob_to_digest(&bytes, "mmr_nodes.node_hash")
}

/// Persists newly created MMR nodes for `leaf_index` inside an active SQLite transaction
/// and returns the resulting 32-byte MMR root digest.
pub(crate) fn append_mmr_in_tx(
    tx: &Transaction<'_>,
    repo_id: &RepoId,
    stream: StreamKind,
    leaf_index: u64,
    record_hash: BlobDigest,
) -> Result<BlobDigest, StoreError> {
    let prior_positions = peak_positions(leaf_index);
    let mut prior_peaks = Vec::with_capacity(prior_positions.len());
    for pos in prior_positions {
        prior_peaks.push(fetch_node(tx, repo_id, stream, pos)?);
    }

    let out = compute_append_nodes(leaf_index, record_hash, &prior_peaks)
        .map_err(|e| StoreError::Backend(format!("mmr append: {e}")))?;

    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO mmr_nodes (repo_id, stream_kind, pos, node_hash)
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(sqlite_err)?;
        for (pos, hash) in &out.created_nodes {
            stmt.execute(params![
                repo_id.as_str(),
                stream.as_str(),
                *pos as i64,
                hash.as_bytes().as_slice(),
            ])
            .map_err(sqlite_err)?;
        }
    }
    Ok(bag_mmr_peaks(leaf_index + 1, &out.next_peaks))
}

/// Builds an `O(log N)` [`MmrProof`] for `leaf_index` using primary-key lookups against `mmr_nodes`.
pub(crate) fn query_inclusion_proof_sync(
    conn: &Connection,
    repo_id: &RepoId,
    stream: StreamKind,
    leaf_index: u64,
    leaf_count: u64,
) -> Result<MmrProof, StoreError> {
    let plan = proof_node_positions(leaf_index, leaf_count)
        .map_err(|e| StoreError::InvalidInput(e.to_string()))?;
    let mut siblings = Vec::with_capacity(plan.sibling_positions.len());
    for (pos, is_right) in plan.sibling_positions {
        let hash = fetch_node(conn, repo_id, stream, pos)?;
        siblings.push(MmrSibling { hash, is_right });
    }
    let mut peaks = Vec::with_capacity(plan.peak_positions.len());
    for pos in plan.peak_positions {
        peaks.push(fetch_node(conn, repo_id, stream, pos)?);
    }
    Ok(MmrProof {
        leaf_index,
        leaf_count,
        siblings,
        peaks,
        peak_index: plan.peak_index,
    })
}
