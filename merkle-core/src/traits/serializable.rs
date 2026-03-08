//! # merkle-core :: traits :: serializable
//!
//! The `Serializable` trait ensures that both tree state *and* generated
//! proofs can be persisted to a database or transmitted over a network
//! without compatibility issues.
//!
//! The default implementation uses `bincode` for compact binary encoding,
//! but the trait is open — implementors can substitute a different codec
//! (e.g. JSON, CBOR, RLP) by overriding the methods.

use crate::error::MerkleError;
use serde::{de::DeserializeOwned, Serialize};

/// Trait for types that can be serialised to / deserialised from bytes.
///
/// # Default implementation
/// The blanket impl below provides default `to_bytes` / `from_bytes`
/// methods for any type that derives `serde::Serialize + DeserializeOwned`,
/// using `bincode` for compact binary encoding.
pub trait Serializable: Sized {
    /// Serialise `self` to a `Vec<u8>`.
    ///
    /// # Errors
    /// Returns [`MerkleError::SerializationError`] if the codec fails.
    fn to_bytes(&self) -> Result<Vec<u8>, MerkleError>;

    /// Reconstruct `Self` from a byte slice.
    ///
    /// # Errors
    /// Returns [`MerkleError::DeserializationError`] if the slice is
    /// malformed or the wrong length.
    fn from_bytes(bytes: &[u8]) -> Result<Self, MerkleError>;

    /// Return the serialised size in bytes without allocating.
    ///
    /// The default implementation serialises and measures — override for
    /// O(1) size calculation where the size is statically known.
    fn serialized_size(&self) -> Result<usize, MerkleError> {
        Ok(self.to_bytes()?.len())
    }
}

// ── Blanket implementation ─────────────────────────────────────────────────

/// Automatically implement `Serializable` for any `serde`-compatible type.
///
/// This covers `MerkleProof<D>`, `TreeMetadata`, and any future types that
/// derive `Serialize + DeserializeOwned`.
impl<T: Serialize + DeserializeOwned> Serializable for T {
    fn to_bytes(&self) -> Result<Vec<u8>, MerkleError> {
        bincode::serialize(self).map_err(MerkleError::from)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, MerkleError> {
        bincode::deserialize(bytes)
            .map_err(|e| MerkleError::DeserializationError(e.to_string()))
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{LeafIndex, MerkleProof, ProofNode, ProofSide};

    fn sample_proof() -> MerkleProof<[u8; 32]> {
        MerkleProof {
            leaf_index: LeafIndex(1),
            leaf_count: 4,
            path: vec![
                ProofNode { hash: [0xAB; 32], side: ProofSide::Left },
                ProofNode { hash: [0xCD; 32], side: ProofSide::Right },
            ],
        }
    }

    #[test]
    fn round_trip_proof() {
        let proof = sample_proof();
        let bytes = proof.to_bytes().expect("serialise");
        let recovered = MerkleProof::<[u8; 32]>::from_bytes(&bytes).expect("deserialise");
        assert_eq!(proof, recovered);
    }

    #[test]
    fn serialized_size_is_positive() {
        let proof = sample_proof();
        let size = proof.serialized_size().expect("size");
        assert!(size > 0);
    }

    #[test]
    fn from_bytes_rejects_garbage() {
        let bad = b"this is not valid bincode data...........";
        let result = MerkleProof::<[u8; 32]>::from_bytes(bad);
        assert!(result.is_err());
    }
}
