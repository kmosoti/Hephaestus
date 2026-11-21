//! Deterministic JSON/BLAKE3 codecs for Jujutsu (`jj-lib`) objects stored in Hephaestus CAS.

use hephaestus_core::BlobDigest;
use jj_lib::backend::{
    BackendError, BackendResult, ChangeId, Commit, CommitId, CopyId, FileId, MillisSinceEpoch,
    SecureSig, Signature, SymlinkId, Timestamp, Tree, TreeId, TreeValue,
};
use jj_lib::conflict_labels::ConflictLabels;
use jj_lib::merge::MergeBuilder;
use jj_lib::object_id::ObjectId;
use jj_lib::repo_path::RepoPathComponentBuf;
use serde::{Deserialize, Serialize};

/// Content-addressed manifest mapping a Jujutsu `FileId` to its ordered FastCDC chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasFileManifest {
    /// Original total file length in bytes.
    pub total_len: u64,
    /// Ordered 64-char hex BLAKE3 digests of each FastCDC chunk.
    pub chunks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CasTreeValue {
    File {
        id: String,
        executable: bool,
        copy_id: String,
    },
    Symlink {
        id: String,
    },
    Tree {
        id: String,
    },
    GitSubmodule {
        id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CasTreeEntry {
    name: String,
    value: CasTreeValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CasTree {
    entries: Vec<CasTreeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CasSignature {
    name: String,
    email: String,
    millis: i64,
    tz_offset: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CasCommit {
    parents: Vec<String>,
    predecessors: Vec<String>,
    root_tree: Vec<String>,
    conflict_labels: Vec<String>,
    change_id: String,
    description: String,
    author: CasSignature,
    committer: CasSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secure_sig: Option<String>,
}

fn codec_err(msg: impl Into<String>) -> BackendError {
    BackendError::Other(msg.into().into())
}

fn decode_hex_bytes(s: &str) -> BackendResult<Vec<u8>> {
    hex::decode(s).map_err(|e| codec_err(format!("invalid object hex `{s}`: {e}")))
}

/// Encodes a Jujutsu [`Tree`] canonically and returns `(bytes, blake3_digest)`.
pub(crate) fn encode_tree(tree: &Tree) -> BackendResult<(Vec<u8>, BlobDigest)> {
    let mut entries = Vec::new();
    for entry in tree.entries() {
        let value = match entry.value() {
            TreeValue::File {
                id,
                executable,
                copy_id,
            } => CasTreeValue::File {
                id: id.hex(),
                executable: *executable,
                copy_id: copy_id.hex(),
            },
            TreeValue::Symlink(id) => CasTreeValue::Symlink { id: id.hex() },
            TreeValue::Tree(id) => CasTreeValue::Tree { id: id.hex() },
            TreeValue::GitSubmodule(id) => CasTreeValue::GitSubmodule { id: id.hex() },
        };
        entries.push(CasTreeEntry {
            name: entry.name().as_internal_str().to_owned(),
            value,
        });
    }
    let bytes = serde_json::to_vec(&CasTree { entries })
        .map_err(|e| codec_err(format!("encode tree: {e}")))?;
    let digest = BlobDigest::of(&bytes);
    Ok((bytes, digest))
}

/// Decodes a Jujutsu [`Tree`] from its canonical CAS JSON bytes.
pub(crate) fn decode_tree(bytes: &[u8]) -> BackendResult<Tree> {
    let parsed: CasTree =
        serde_json::from_slice(bytes).map_err(|e| codec_err(format!("decode tree: {e}")))?;
    let mut entries = Vec::with_capacity(parsed.entries.len());
    for e in parsed.entries {
        let name = RepoPathComponentBuf::new(e.name)
            .map_err(|err| codec_err(format!("invalid tree entry name: {err}")))?;
        let val = match e.value {
            CasTreeValue::File {
                id,
                executable,
                copy_id,
            } => TreeValue::File {
                id: FileId::new(decode_hex_bytes(&id)?),
                executable,
                copy_id: CopyId::new(decode_hex_bytes(&copy_id)?),
            },
            CasTreeValue::Symlink { id } => {
                TreeValue::Symlink(SymlinkId::new(decode_hex_bytes(&id)?))
            }
            CasTreeValue::Tree { id } => TreeValue::Tree(TreeId::new(decode_hex_bytes(&id)?)),
            CasTreeValue::GitSubmodule { id } => {
                TreeValue::GitSubmodule(CommitId::new(decode_hex_bytes(&id)?))
            }
        };
        entries.push((name, val));
    }
    Ok(Tree::from_sorted_entries(entries))
}

/// Returns the canonical serialized bytes and BLAKE3 digest of an empty Jujutsu [`Tree`].
pub(crate) fn empty_tree_bytes_and_digest() -> (Vec<u8>, BlobDigest) {
    let bytes = br#"{"entries":[]}"#.to_vec();
    let digest = BlobDigest::of(&bytes);
    (bytes, digest)
}

fn to_cas_sig(sig: &Signature) -> CasSignature {
    CasSignature {
        name: sig.name.clone(),
        email: sig.email.clone(),
        millis: sig.timestamp.timestamp.0,
        tz_offset: sig.timestamp.tz_offset,
    }
}

fn from_cas_sig(sig: CasSignature) -> Signature {
    Signature {
        name: sig.name,
        email: sig.email,
        timestamp: Timestamp {
            timestamp: MillisSinceEpoch(sig.millis),
            tz_offset: sig.tz_offset,
        },
    }
}

/// Encodes a Jujutsu [`Commit`] (without signature) for signing, and optionally attaches `sig_hex`.
pub(crate) fn encode_commit(
    commit: &Commit,
    sig_bytes: Option<&[u8]>,
) -> BackendResult<(Vec<u8>, BlobDigest)> {
    let dto = CasCommit {
        parents: commit.parents.iter().map(ObjectId::hex).collect(),
        predecessors: commit.predecessors.iter().map(ObjectId::hex).collect(),
        root_tree: commit.root_tree.iter().map(ObjectId::hex).collect(),
        conflict_labels: if commit.conflict_labels.is_resolved() {
            Vec::new()
        } else {
            commit.conflict_labels.as_slice().to_vec()
        },
        change_id: commit.change_id.hex(),
        description: commit.description.clone(),
        author: to_cas_sig(&commit.author),
        committer: to_cas_sig(&commit.committer),
        secure_sig: sig_bytes.map(hex::encode),
    };
    let bytes = serde_json::to_vec(&dto).map_err(|e| codec_err(format!("encode commit: {e}")))?;
    let digest = BlobDigest::of(&bytes);
    Ok((bytes, digest))
}

/// Decodes a Jujutsu [`Commit`] from its canonical CAS JSON bytes.
pub(crate) fn decode_commit(bytes: &[u8]) -> BackendResult<Commit> {
    let mut dto: CasCommit =
        serde_json::from_slice(bytes).map_err(|e| codec_err(format!("decode commit: {e}")))?;
    let secure_sig = match dto.secure_sig.take() {
        Some(sig_hex) => {
            let sig = decode_hex_bytes(&sig_hex)?;
            let unsigned = serde_json::to_vec(&dto)
                .map_err(|e| codec_err(format!("re-encode unsigned commit: {e}")))?;
            Some(SecureSig {
                data: unsigned,
                sig,
            })
        }
        None => None,
    };

    let parents = dto
        .parents
        .iter()
        .map(|s| decode_hex_bytes(s).map(CommitId::new))
        .collect::<BackendResult<Vec<_>>>()?;
    let predecessors = dto
        .predecessors
        .iter()
        .map(|s| decode_hex_bytes(s).map(CommitId::new))
        .collect::<BackendResult<Vec<_>>>()?;
    let tree_ids = dto
        .root_tree
        .iter()
        .map(|t| decode_hex_bytes(t).map(TreeId::new))
        .collect::<BackendResult<Vec<_>>>()?;
    let tree_builder: MergeBuilder<_> = tree_ids.into_iter().collect();
    let root_tree = tree_builder.build();
    let conflict_labels = ConflictLabels::from_vec(dto.conflict_labels).into_merge();
    let change_id = ChangeId::new(decode_hex_bytes(&dto.change_id)?);

    Ok(Commit {
        parents,
        predecessors,
        root_tree,
        conflict_labels,
        change_id,
        description: dto.description,
        author: from_cas_sig(dto.author),
        committer: from_cas_sig(dto.committer),
        secure_sig,
    })
}
