//! Validated repository, change, commit, and operation identifiers.

use alloc::borrow::ToOwned;
use alloc::string::String;
use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_ID_LEN: usize = 256;

/// Validation error for repository and Jujutsu object identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    /// Identifier is empty or whitespace-only.
    #[error("{kind} identifier must not be empty")]
    Empty {
        /// Human-readable kind label (`repo`, `change_id`, `commit_id`, `op_id`).
        kind: &'static str,
    },
    /// Identifier exceeds the maximum permitted byte length.
    #[error("{kind} identifier exceeds maximum length of {max} bytes")]
    TooLong {
        /// Human-readable kind label.
        kind: &'static str,
        /// Maximum length in bytes.
        max: usize,
    },
    /// Identifier contains forbidden control, whitespace, or path-traversal characters.
    #[error("{kind} identifier contains invalid characters")]
    InvalidCharacters {
        /// Human-readable kind label.
        kind: &'static str,
    },
}

fn validate_id(kind: &'static str, raw: &str, allow_slash: bool) -> Result<String, IdError> {
    if raw.is_empty() {
        return Err(IdError::Empty { kind });
    }
    if raw.len() > MAX_ID_LEN {
        return Err(IdError::TooLong {
            kind,
            max: MAX_ID_LEN,
        });
    }
    if raw.contains("..") || raw.starts_with('/') || raw.ends_with('/') {
        return Err(IdError::InvalidCharacters { kind });
    }
    for b in raw.bytes() {
        let ok = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.')
            || (allow_slash && b == b'/');
        if !ok {
            return Err(IdError::InvalidCharacters { kind });
        }
    }
    Ok(raw.to_owned())
}

macro_rules! id_newtype {
    ($name:ident, $kind:literal, $allow_slash:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let raw = String::deserialize(deserializer)?;
                Self::parse(&raw).map_err(serde::de::Error::custom)
            }
        }

        impl $name {
            /// Validates and constructs an identifier.
            pub fn parse(raw: &str) -> Result<Self, IdError> {
                validate_id($kind, raw, $allow_slash).map(Self)
            }

            /// Returns the underlying string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_newtype!(RepoId, "repo", true, "Validated repository identifier.");
id_newtype!(
    ChangeId,
    "change_id",
    false,
    "Validated Jujutsu ChangeId (stable across commit rewrites)."
);
id_newtype!(
    CommitId,
    "commit_id",
    false,
    "Validated Jujutsu CommitId (content-addressed commit revision)."
);
id_newtype!(
    OpId,
    "op_id",
    false,
    "Validated Jujutsu OperationId in the operation log."
);
