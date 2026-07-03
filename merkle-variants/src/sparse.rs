//! Sparse Merkle tree implementation.
//!
//! [`SparseMerkleTree`] models a fixed-depth 256-bit key space where most
//! leaves are empty. The initial implementation stores only non-empty nodes
//! and precomputes the empty subtree hash at every level.
//!
//! # Example
//!
//! ```
//! use merkle_variants::SparseMerkleTree;
//! use merkleforge_hash::{HashFunction, Sha256};
//!
//! let tree = SparseMerkleTree::<Sha256>::new();
//!
//! assert!(tree.is_empty());
//! assert_eq!(tree.leaf_count(), 0);
//! assert_eq!(tree.height(), 256);
//! assert_eq!(tree.root(), tree.empty_hash_at(256));
//! assert_eq!(tree.empty_hash_at(0), &Sha256::empty());
//! ```

use std::collections::HashMap;

use merkle_core::traits::HashFunction;

/// Fixed tree depth for MerkleForge sparse Merkle trees.
pub const SPARSE_TREE_DEPTH: usize = 256;

/// Number of cached empty hashes (levels 0..=256) in a 256-depth sparse Merkle tree.
pub const EMPTY_HASH_LEVELS: usize = SPARSE_TREE_DEPTH + 1;

/// A sparse Merkle tree over a 256-bit key space.
///
/// The tree stores only non-empty nodes in a hash map keyed by their compact
/// 256-bit path. Empty subtrees are represented by a precomputed hash cache:
/// index `0` is the empty leaf hash and index `256` is the root of a fully
/// empty tree.
pub struct SparseMerkleTree<H: HashFunction> {
    nodes: HashMap<[u8; 32], H::Digest>,
    leaf_count: usize,
    depth: usize,
    empty_hashes: Vec<H::Digest>,
}

impl<H: HashFunction> SparseMerkleTree<H> {
    /// Creates an empty sparse Merkle tree with a precomputed empty-hash cache.
    ///
    /// Initialization is `O(256)`: the tree starts with [`HashFunction::empty`]
    /// at leaf level `0`, then derives each parent level with
    /// [`HashFunction::hash_nodes`] over the previous empty hash.
    #[must_use]
    pub fn new() -> Self {
        let mut empty_hashes = Vec::with_capacity(EMPTY_HASH_LEVELS);
        empty_hashes.push(H::empty());

        for level in 1..=SPARSE_TREE_DEPTH {
            let previous = &empty_hashes[level - 1];
            empty_hashes.push(H::hash_nodes(previous, previous));
        }

        Self {
            nodes: HashMap::new(),
            leaf_count: 0,
            depth: SPARSE_TREE_DEPTH,
            empty_hashes,
        }
    }

    /// Returns the current root hash.
    ///
    /// For a newly-created empty tree this is the cached empty hash at level
    /// `256`.
    #[must_use]
    pub fn root(&self) -> &H::Digest {
        &self.empty_hashes[self.depth]
    }

    /// Returns the number of non-empty leaves currently stored.
    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns `true` when the tree has no non-empty leaves.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    /// Returns the fixed sparse tree height.
    #[must_use]
    pub const fn height(&self) -> usize {
        self.depth
    }

    /// Returns the cached empty hash for `level`.
    ///
    /// Level `0` is the empty leaf hash and level `256` is the empty-tree root.
    ///
    /// # Panics
    ///
    /// Panics when `level` is greater than [`SPARSE_TREE_DEPTH`].
    #[must_use]
    pub fn empty_hash_at(&self, level: usize) -> &H::Digest {
        assert!(
            level <= self.depth,
            "empty_hash_at: level {} out of range (max {})",
            level,
            self.depth
        );
        &self.empty_hashes[level]
    }

    /// Returns the full empty-hash cache.
    ///
    /// The slice always contains [`EMPTY_HASH_LEVELS`] entries.
    #[must_use]
    pub fn empty_hashes(&self) -> &[H::Digest] {
        &self.empty_hashes
    }

    /// Returns the number of non-empty nodes currently materialized.
    #[must_use]
    pub fn stored_node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl<H: HashFunction> Default for SparseMerkleTree<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use merkle_core::traits::HashFunction;
    use merkleforge_hash::Sha256;

    use super::{EMPTY_HASH_LEVELS, SPARSE_TREE_DEPTH, SparseMerkleTree};

    #[test]
    fn new_tree_has_empty_sparse_shape() {
        let tree = SparseMerkleTree::<Sha256>::new();

        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.height(), SPARSE_TREE_DEPTH);
        assert_eq!(tree.stored_node_count(), 0);
    }

    #[test]
    fn empty_tree_root_is_cached_root_level() {
        let tree = SparseMerkleTree::<Sha256>::new();

        assert_eq!(tree.root(), tree.empty_hash_at(SPARSE_TREE_DEPTH));
    }

    #[test]
    fn empty_hash_cache_has_one_entry_per_level() {
        let tree = SparseMerkleTree::<Sha256>::new();

        assert_eq!(tree.empty_hashes().len(), EMPTY_HASH_LEVELS);
        assert_eq!(tree.empty_hash_at(0), &Sha256::empty());
    }

    #[test]
    fn empty_hash_cache_is_derived_bottom_up() {
        let tree = SparseMerkleTree::<Sha256>::new();

        for level in 1..=SPARSE_TREE_DEPTH {
            let previous = tree.empty_hash_at(level - 1);
            let expected = Sha256::hash_nodes(previous, previous);

            assert_eq!(tree.empty_hash_at(level), &expected);
        }
    }
}
