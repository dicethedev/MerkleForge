//! # merkle-core :: traits :: merkle_tree
//!
//! The `MerkleTree` trait defines the **universal interface** that every
//! tree variant (binary, sparse, Patricia) must implement.  It is
//! deliberately minimal — only the operations needed by the proof system
//! and the benchmarking suite are mandated here.  Variant-specific
//! optimisations (e.g. batch updates for sparse trees) live in the
//! respective `merkle-variants` sub-crates.

use crate::{
    error::MerkleError,
    traits::HashFunction,
    types::{LeafIndex, MerkleProof, TreeMetadata},
};

/// Universal interface for a Merkle tree parameterised over a hash function.
///
/// # Type parameters
/// - `H`: A [`HashFunction`] that determines the digest type and hashing
///   strategy.
///
/// # Implementors
/// Implementors live in `merkle-variants`:
/// - `BinaryMerkleTree<H>` — balanced, optimised for transaction batching.
/// - `SparseMerkleTree<H>` — 256-bit key space, optimised for state storage.
/// - `MerklePatriciaTrie<H>` — Ethereum-compatible, RLP-encoded trie.
pub trait MerkleTree<H: HashFunction> {
    // ── Mutation ──────────────────────────────────────────────────────────

    /// Insert a new leaf with the given raw data.
    ///
    /// The data is hashed internally; the caller provides the *pre-image*.
    ///
    /// # Errors
    /// - [`MerkleError::EmptyLeafData`] if `data` is empty.
    /// - Variant-specific errors if internal restructuring fails.
    fn insert(&mut self, data: &[u8]) -> Result<LeafIndex, MerkleError>;

    /// Remove the leaf at `index` by replacing it with the empty hash.
    ///
    /// # Errors
    /// - [`MerkleError::EmptyTree`] if the tree has no leaves.
    /// - [`MerkleError::IndexOutOfBounds`] if `index >= leaf_count`.
    fn remove(&mut self, index: LeafIndex) -> Result<(), MerkleError>;

    // ── Queries ───────────────────────────────────────────────────────────

    /// Return the current root digest, or `None` if the tree is empty.
    fn root(&self) -> Option<&H::Digest>;

    /// Return the number of *leaf* slots currently in the tree.
    ///
    /// For power-of-two trees this may be larger than the number of
    /// meaningful inserts because the tree is padded with empty hashes.
    fn leaf_count(&self) -> usize;

    /// Return `true` if the tree contains no meaningful leaves.
    fn is_empty(&self) -> bool {
        self.leaf_count() == 0
    }

    /// Return the height of the tree.
    ///
    /// An empty tree has height 0; a single-leaf tree has height 1; a tree
    /// with `n` leaves has height `⌈log₂(n)⌉ + 1`.
    fn height(&self) -> usize;

    // ── Proof generation ──────────────────────────────────────────────────

    /// Generate an inclusion proof for the leaf at `index`.
    ///
    /// The proof allows a stateless verifier to confirm that the leaf is
    /// part of the tree without downloading the entire dataset — only the
    /// `O(log n)` sibling hashes along the path to the root are required.
    ///
    /// # Errors
    /// - [`MerkleError::EmptyTree`] if there are no leaves.
    /// - [`MerkleError::IndexOutOfBounds`] if `index >= leaf_count`.
    fn generate_proof(&self, index: LeafIndex) -> Result<MerkleProof<H::Digest>, MerkleError>;

    // ── Metadata ──────────────────────────────────────────────────────────

    /// Return a lightweight metadata snapshot of the current tree state.
    fn metadata(&self) -> TreeMetadata;
}

// ── ProofVerifier (stateless) ─────────────────────────────────────────────

/// Stateless proof verification.
///
/// A `ProofVerifier` does **not** need to hold the full tree.  Given only
/// the root hash and a [`MerkleProof`], it can determine whether a specific
/// leaf belongs to the tree — this is the "light client" property shown in
/// the architecture diagram.
///
/// This is a *separate* trait so it can be implemented on a zero-sized
/// struct (no tree state whatsoever) and used in constrained environments.
pub trait ProofVerifier<H: HashFunction> {
    /// Verify that `leaf_data` is the leaf at `proof.leaf_index` in a tree
    /// with the given `root`.
    ///
    /// Returns `true` iff the reconstructed root matches `expected_root`.
    ///
    /// # Arguments
    /// - `expected_root`: The trusted root hash (e.g. from a block header).
    /// - `leaf_data`: The raw pre-image bytes of the leaf being verified.
    /// - `proof`: The [`MerkleProof`] for this leaf.
    fn verify(expected_root: &H::Digest, leaf_data: &[u8], proof: &MerkleProof<H::Digest>) -> bool;
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// These tests validate the *contract* expressed by the trait, not any
    /// specific implementation.  Concrete tree tests live in merkle-variants.
    use super::*;

    // Ensure the trait is object-safe enough that we can write bounds.
    fn _assert_object_safe<H: HashFunction>(_t: &dyn MerkleTree<H>) {}
}
