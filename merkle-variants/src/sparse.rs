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
//! assert_eq!(tree.height(), 0);
//! assert_eq!(tree.depth(), 256);
//! assert_eq!(tree.root(), None);
//! assert_eq!(tree.empty_root(), tree.empty_hash_at(256));
//! assert_eq!(tree.empty_hash_at(0), &Sha256::empty());
//! ```

use std::collections::HashMap;

use merkle_core::{error::MerkleError, traits::HashFunction};

/// Fixed tree depth for MerkleForge sparse Merkle trees.
pub const SPARSE_TREE_DEPTH: usize = 256;

/// Number of cached empty hashes (levels 0..=256) in a 256-depth sparse Merkle tree.
pub const EMPTY_HASH_LEVELS: usize = SPARSE_TREE_DEPTH + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NodeKey {
    depth: usize,
    path: [u8; 32],
}

impl NodeKey {
    fn new(key: [u8; 32], depth: usize) -> Self {
        debug_assert!(depth <= SPARSE_TREE_DEPTH);

        let mut path = [0_u8; 32];
        let full_bytes = depth / 8;
        let remaining_bits = depth % 8;

        path[..full_bytes].copy_from_slice(&key[..full_bytes]);
        if remaining_bits > 0 {
            let mask = u8::MAX << (8 - remaining_bits);
            path[full_bytes] = key[full_bytes] & mask;
        }

        Self { depth, path }
    }

    fn leaf(key: [u8; 32]) -> Self {
        Self::new(key, SPARSE_TREE_DEPTH)
    }

    fn sibling(key: [u8; 32], depth: usize) -> Self {
        debug_assert!(depth > 0);

        let mut sibling = Self::new(key, depth);
        let bit_index = depth - 1;
        let byte_index = bit_index / 8;
        let bit_offset = 7 - (bit_index % 8);
        sibling.path[byte_index] ^= 1 << bit_offset;
        sibling
    }
}

/// A sparse Merkle tree over a 256-bit key space.
///
/// The tree stores only non-empty nodes in a hash map keyed by their depth and
/// compact 256-bit path. Empty subtrees are represented by a precomputed hash
/// cache: index `0` is the empty leaf hash and index `256` is the root of a
/// fully empty tree.
pub struct SparseMerkleTree<H: HashFunction> {
    nodes: HashMap<NodeKey, H::Digest>,
    leaf_count: usize,
    depth: usize,
    root: H::Digest,
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
        let root = empty_hashes[SPARSE_TREE_DEPTH].clone();

        Self {
            nodes: HashMap::new(),
            leaf_count: 0,
            depth: SPARSE_TREE_DEPTH,
            root,
            empty_hashes,
        }
    }

    /// Inserts or overwrites the leaf at `key` with `data`.
    ///
    /// The value is hashed with [`HashFunction::hash`] before being stored.
    /// Only the 256 nodes on the key path are recomputed; missing siblings use
    /// the precomputed empty-hash cache.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::EmptyLeafData`] when `data` is empty.
    pub fn insert(&mut self, key: [u8; 32], data: &[u8]) -> Result<(), MerkleError> {
        if data.is_empty() {
            return Err(MerkleError::EmptyLeafData);
        }

        let leaf_key = NodeKey::leaf(key);
        let was_empty = self.nodes.insert(leaf_key, H::hash(data)).is_none();
        if was_empty {
            self.leaf_count += 1;
        }
        self.recompute_path(key);

        Ok(())
    }

    /// Removes the leaf stored at `key`.
    ///
    /// After removing the leaf, the tree recomputes and prunes the path back
    /// to the root using cached empty hashes for missing siblings.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::UnsupportedOperation`] when no leaf exists for
    /// `key`.
    pub fn remove(&mut self, key: [u8; 32]) -> Result<(), MerkleError> {
        let leaf_key = NodeKey::leaf(key);
        if self.nodes.remove(&leaf_key).is_none() {
            return Err(MerkleError::UnsupportedOperation(
                "remove missing sparse key",
            ));
        }

        self.leaf_count -= 1;
        self.recompute_path(key);

        Ok(())
    }

    /// Returns the hashed leaf stored at `key`, if any.
    #[must_use]
    pub fn get(&self, key: [u8; 32]) -> Option<&H::Digest> {
        self.nodes.get(&NodeKey::leaf(key))
    }

    /// Returns the current root hash, or `None` when the tree has no
    /// non-empty leaves.
    ///
    /// Use [`Self::empty_root`] when callers need the canonical root of a
    /// fully empty sparse tree.
    #[must_use]
    pub fn root(&self) -> Option<&H::Digest> {
        if self.is_empty() {
            return None;
        }

        Some(&self.root)
    }

    /// Returns the root hash of a fully empty sparse Merkle tree.
    ///
    /// This is the cached empty hash at level `256`.
    #[must_use]
    pub fn empty_root(&self) -> &H::Digest {
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

    /// Returns the current Merkle tree height.
    ///
    /// This follows the shared [`merkle_core::traits::MerkleTree`] contract:
    /// an empty tree has height `0`.
    #[must_use]
    pub const fn height(&self) -> usize {
        if self.leaf_count == 0 { 0 } else { self.depth }
    }

    /// Returns the fixed sparse key-space depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
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

    fn recompute_path(&mut self, key: [u8; 32]) {
        let leaf_key = NodeKey::leaf(key);
        let (mut current_hash, mut current_exists) = match self.nodes.get(&leaf_key) {
            Some(digest) => (digest.clone(), true),
            None => (self.empty_hashes[0].clone(), false),
        };

        for depth in (1..=self.depth).rev() {
            let sibling_key = NodeKey::sibling(key, depth);
            let empty_level = self.depth - depth;
            let (sibling_hash, sibling_exists) = match self.nodes.get(&sibling_key) {
                Some(digest) => (digest.clone(), true),
                None => (self.empty_hashes[empty_level].clone(), false),
            };

            let parent_hash = if bit_at(&key, depth - 1) {
                H::hash_nodes(&sibling_hash, &current_hash)
            } else {
                H::hash_nodes(&current_hash, &sibling_hash)
            };
            let parent_exists = current_exists || sibling_exists;
            let parent_key = NodeKey::new(key, depth - 1);

            if parent_exists {
                self.nodes.insert(parent_key, parent_hash.clone());
            } else {
                self.nodes.remove(&parent_key);
            }

            current_hash = parent_hash;
            current_exists = parent_exists;
        }

        self.root = current_hash;
    }
}

/// Returns the bit at `depth` in `key`, reading most-significant bit first.
///
/// `depth` must be in the range `0..256`, where `0` is the high bit of
/// `key[0]` and `255` is the low bit of `key[31]`.
///
/// # Panics
///
/// Panics when `depth` is greater than or equal to [`SPARSE_TREE_DEPTH`].
#[must_use]
pub fn bit_at(key: &[u8; 32], depth: usize) -> bool {
    assert!(
        depth < SPARSE_TREE_DEPTH,
        "bit_at: depth {} out of range (max {})",
        depth,
        SPARSE_TREE_DEPTH - 1
    );

    let byte_index = depth / 8;
    let bit_offset = 7 - (depth % 8);
    key[byte_index] & (1 << bit_offset) != 0
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

    use merkle_core::error::MerkleError;

    use super::{EMPTY_HASH_LEVELS, SPARSE_TREE_DEPTH, SparseMerkleTree, bit_at};

    #[test]
    fn new_tree_has_empty_sparse_shape() {
        let tree = SparseMerkleTree::<Sha256>::new();

        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.depth(), SPARSE_TREE_DEPTH);
        assert_eq!(tree.stored_node_count(), 0);
    }

    #[test]
    fn empty_tree_root_is_cached_root_level() {
        let tree = SparseMerkleTree::<Sha256>::new();

        assert_eq!(tree.root(), None);
        assert_eq!(tree.empty_root(), tree.empty_hash_at(SPARSE_TREE_DEPTH));
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

    #[test]
    fn bit_at_reads_key_msb_first() {
        let mut key = [0_u8; 32];
        key[0] = 0b1000_0001;
        key[31] = 0b0000_0001;

        assert!(bit_at(&key, 0));
        assert!(!bit_at(&key, 1));
        assert!(bit_at(&key, 7));
        assert!(bit_at(&key, 255));
    }

    #[test]
    fn insert_rejects_empty_leaf_data() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [7_u8; 32];

        assert_eq!(tree.insert(key, b""), Err(MerkleError::EmptyLeafData));
        assert!(tree.is_empty());
        assert_eq!(tree.root(), None);
    }

    #[test]
    fn insert_one_key_changes_root_and_stores_leaf_hash() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [1_u8; 32];
        let empty_root = *tree.empty_root();

        tree.insert(key, b"alice").unwrap();

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.height(), SPARSE_TREE_DEPTH);
        assert_eq!(tree.get(key), Some(&Sha256::hash(b"alice")));
        assert_ne!(tree.root(), Some(&empty_root));
    }

    #[test]
    fn insert_then_remove_returns_to_empty_root() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [2_u8; 32];
        let empty_root = *tree.empty_root();

        tree.insert(key, b"alice").unwrap();
        tree.remove(key).unwrap();

        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.get(key), None);
        assert_eq!(tree.root(), None);
        assert_eq!(tree.root, empty_root);
        assert_eq!(*tree.empty_root(), empty_root);
    }

    #[test]
    fn remove_missing_key_is_rejected() {
        let mut tree = SparseMerkleTree::<Sha256>::new();

        assert_eq!(
            tree.remove([3_u8; 32]),
            Err(MerkleError::UnsupportedOperation(
                "remove missing sparse key"
            ))
        );
    }

    #[test]
    fn overwriting_same_key_does_not_double_count() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [4_u8; 32];

        tree.insert(key, b"alice").unwrap();
        let first_root = *tree.root().unwrap();
        tree.insert(key, b"alice updated").unwrap();

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.get(key), Some(&Sha256::hash(b"alice updated")));
        assert_ne!(tree.root(), Some(&first_root));
    }

    #[test]
    fn different_keys_produce_different_roots() {
        let mut first = SparseMerkleTree::<Sha256>::new();
        let mut second = SparseMerkleTree::<Sha256>::new();

        first.insert([5_u8; 32], b"alice").unwrap();
        second.insert([6_u8; 32], b"alice").unwrap();

        assert_ne!(first.root(), second.root());
    }

    #[test]
    fn removing_one_of_two_keys_preserves_other_leaf() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let first = [8_u8; 32];
        let second = [9_u8; 32];

        tree.insert(first, b"alice").unwrap();
        tree.insert(second, b"bob").unwrap();
        tree.remove(first).unwrap();

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.get(first), None);
        assert_eq!(tree.get(second), Some(&Sha256::hash(b"bob")));
        assert!(tree.root().is_some());
    }
}
