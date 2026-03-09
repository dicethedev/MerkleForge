//! # merkle-core :: error
//!
//! Unified error type for the entire `MerkleForge` workspace.
//! Every public fallible function returns `Result<T, MerkleError>`.
//!
//! ## Design notes
//! - `#[non_exhaustive]` lets us add variants in minor releases without
//!   breaking downstream match expressions.
//! - Each variant carries enough context for the caller to act on the
//!   error without needing to inspect a string message.

use std::fmt;

/// All errors that can arise from the `MerkleForge` crates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MerkleError {
    /// An operation that requires at least one leaf was attempted on an
    /// empty tree.
    EmptyTree,

    /// A leaf or node index exceeded the bounds of the current tree.
    IndexOutOfBounds {
        /// The index that was requested.
        index: usize,
        /// The number of leaves/nodes currently in the tree.
        len: usize,
    },

    /// Proof verification failed — the supplied proof does not produce the
    /// expected root hash.
    InvalidProof,

    /// The leaf count embedded in a proof is inconsistent with the proof
    /// path length or the stated index.
    InvalidProofStructure(String),

    /// The input byte slice was empty where a non-empty value was required.
    EmptyLeafData,

    /// Serialisation to bytes failed.
    SerializationError(String),

    /// Deserialisation from bytes failed (e.g. corrupted data, wrong format).
    DeserializationError(String),

    /// An internal hashing step produced an unexpected result.
    HashError(String),

    /// The requested operation is not supported for this tree variant.
    UnsupportedOperation(&'static str),

    /// RLP encoding / decoding error (used by the Patricia Trie variant).
    RlpError(String),
}

// ── Display ────────────────────────────────────────────────────────────────

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTree => write!(f, "operation requires a non-empty tree"),
            Self::IndexOutOfBounds { index, len } => write!(
                f,
                "index {index} is out of bounds for a tree with {len} leaves"
            ),
            Self::InvalidProof => {
                write!(f, "proof verification failed: computed root does not match")
            }
            Self::InvalidProofStructure(msg) => {
                write!(f, "malformed proof structure: {msg}")
            }
            Self::EmptyLeafData => write!(f, "leaf data must not be empty"),
            Self::SerializationError(msg) => write!(f, "serialisation error: {msg}"),
            Self::DeserializationError(msg) => write!(f, "deserialisation error: {msg}"),
            Self::HashError(msg) => write!(f, "hash computation error: {msg}"),
            Self::UnsupportedOperation(op) => {
                write!(f, "operation '{op}' is not supported for this tree variant")
            }
            Self::RlpError(msg) => write!(f, "RLP codec error: {msg}"),
        }
    }
}

impl std::error::Error for MerkleError {}

// ── Conversions from common I/O / codec errors ─────────────────────────────

impl From<bincode::Error> for MerkleError {
    fn from(e: bincode::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_empty_tree() {
        let e = MerkleError::EmptyTree;
        assert!(e.to_string().contains("non-empty"));
    }

    #[test]
    fn display_out_of_bounds() {
        let e = MerkleError::IndexOutOfBounds { index: 5, len: 3 };
        let msg = e.to_string();
        assert!(msg.contains('5') && msg.contains('3'));
    }

    #[test]
    fn display_invalid_proof() {
        let e = MerkleError::InvalidProof;
        assert!(e.to_string().contains("verification failed"));
    }

    #[test]
    fn error_is_clone_and_eq() {
        let a = MerkleError::EmptyTree;
        let b = a.clone();
        assert_eq!(a, b);
    }
}
