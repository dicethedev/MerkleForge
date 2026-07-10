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
use serde::{Deserialize, Serialize};

/// Fixed tree depth for `MerkleForge` sparse Merkle trees.
pub const SPARSE_TREE_DEPTH: usize = 256;

/// Number of cached empty hashes (levels 0..=256) in a 256-depth sparse Merkle tree.
pub const EMPTY_HASH_LEVELS: usize = SPARSE_TREE_DEPTH + 1;

/// A materialized sparse Merkle tree node.
///
/// Shortcut nodes compress a subtree that contains exactly one leaf. The
/// `prefix` field records the bit length of the compressed subtree root, and
/// `hash` stores that subtree's logical sparse Merkle commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEntry<D> {
    /// A concrete leaf hash stored at depth 256.
    Leaf(D),
    /// A computed internal node hash.
    Internal(D),
    /// A compressed subtree containing exactly one leaf.
    Shortcut {
        /// Bit length of the shortcut prefix.
        prefix: u8,
        /// Logical commitment for the compressed subtree.
        hash: D,
    },
}

/// A key-addressed sparse Merkle membership proof.
///
/// `siblings` are ordered from leaf level to root level and always contain
/// 256 entries. `None` means the sibling subtree is empty and can be
/// reconstructed from the verifier's empty-hash cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseMerkleProof<D> {
    /// The 256-bit key this proof is for.
    pub key: [u8; 32],
    /// Sibling hashes from leaf to root; `None` represents an empty sibling.
    pub siblings: Vec<Option<D>>,
    /// The stored leaf hash, or `None` for a non-membership proof.
    pub leaf: Option<D>,
}

impl<D> SparseMerkleProof<D> {
    /// Returns `true` when this proof contains a stored leaf hash.
    #[must_use]
    pub const fn is_membership(&self) -> bool {
        self.leaf.is_some()
    }

    /// Returns `true` when this proof proves an empty leaf slot.
    #[must_use]
    pub const fn is_non_membership(&self) -> bool {
        self.leaf.is_none()
    }
}

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
    nodes: HashMap<NodeKey, NodeEntry<H::Digest>>,
    leaves: HashMap<[u8; 32], H::Digest>,
    leaf_count: usize,
    depth: usize,
    root: H::Digest,
    empty_hashes: Vec<H::Digest>,
    last_node_accesses: usize,
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
            leaves: HashMap::new(),
            leaf_count: 0,
            depth: SPARSE_TREE_DEPTH,
            root,
            empty_hashes,
            last_node_accesses: 0,
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

        let was_empty = self.leaves.insert(key, H::hash(data)).is_none();
        if was_empty {
            self.leaf_count += 1;
        }
        self.rebuild_shortcuts();

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
        if self.leaves.remove(&key).is_none() {
            return Err(MerkleError::UnsupportedOperation(
                "remove missing sparse key",
            ));
        }

        self.leaf_count -= 1;
        self.rebuild_shortcuts();

        Ok(())
    }

    /// Returns the hashed leaf stored at `key`, if any.
    #[must_use]
    pub fn get(&self, key: [u8; 32]) -> Option<&H::Digest> {
        self.leaves.get(&key)
    }

    /// Generates a sparse Merkle membership proof for `key`.
    ///
    /// The proof contains the stored leaf hash when `key` exists and `None`
    /// otherwise. Empty sibling subtrees are compactly represented as `None`;
    /// verifiers reconstruct those hashes from the canonical empty-hash cache.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::InvalidProofStructure`] if the tree depth cannot
    /// be represented by the proof format. This should not happen for the
    /// fixed `MerkleForge` sparse tree depth.
    pub fn generate_membership_proof(
        &self,
        key: [u8; 32],
    ) -> Result<SparseMerkleProof<H::Digest>, MerkleError> {
        if self.depth != SPARSE_TREE_DEPTH {
            return Err(MerkleError::InvalidProofStructure(
                "sparse tree proof generation requires depth 256".to_string(),
            ));
        }

        let mut siblings = Vec::with_capacity(self.depth);
        for depth in (1..=self.depth).rev() {
            let sibling_key = NodeKey::sibling(key, depth);
            siblings.push(self.subtree_hash_at(sibling_key));
        }

        Ok(SparseMerkleProof {
            key,
            siblings,
            leaf: self.get(key).cloned(),
        })
    }

    /// Returns the current root hash, or `None` when the tree has no
    /// non-empty leaves.
    ///
    /// Use [`Self::empty_root`] when callers need the canonical root of a
    /// fully empty sparse tree.
    #[must_use]
    pub const fn root(&self) -> Option<&H::Digest> {
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

    /// Returns the number of materialized nodes touched by the last rebuild.
    ///
    /// This is primarily useful for validating shortcut-node compression in
    /// tests and benchmarks.
    #[must_use]
    pub const fn last_node_access_count(&self) -> usize {
        self.last_node_accesses
    }

    /// Verifies a sparse Merkle membership proof without needing the tree.
    ///
    /// `leaf_data` is hashed and compared with the proof's embedded leaf hash
    /// before root reconstruction. This ensures a proof for the right key but
    /// wrong value is rejected.
    #[must_use]
    pub fn verify(
        expected_root: &H::Digest,
        leaf_data: &[u8],
        proof: &SparseMerkleProof<H::Digest>,
    ) -> bool {
        if leaf_data.is_empty() || proof.siblings.len() != SPARSE_TREE_DEPTH {
            return false;
        }

        let leaf_hash = H::hash(leaf_data);
        proof.leaf.as_ref() == Some(&leaf_hash)
            && Self::reconstruct_root(&proof.key, leaf_hash, &proof.siblings).as_ref()
                == expected_root.as_ref()
    }

    /// Verifies that `proof.key` is absent from the tree with `expected_root`.
    ///
    /// A non-membership proof is a sparse proof with `leaf: None`. Verification
    /// reconstructs the path with [`HashFunction::empty`] as the leaf hash.
    #[must_use]
    pub fn verify_non_membership(
        expected_root: &H::Digest,
        key: [u8; 32],
        proof: &SparseMerkleProof<H::Digest>,
    ) -> bool {
        proof.key == key
            && proof.is_non_membership()
            && proof.siblings.len() == SPARSE_TREE_DEPTH
            && Self::reconstruct_root(&proof.key, H::empty(), &proof.siblings).as_ref()
                == expected_root.as_ref()
    }

    fn rebuild_shortcuts(&mut self) {
        self.nodes.clear();
        self.last_node_accesses = 0;

        if self.leaves.is_empty() {
            self.root = self.empty_hashes[self.depth].clone();
            return;
        }

        let leaves = self
            .leaves
            .iter()
            .map(|(key, hash)| (*key, hash.clone()))
            .collect::<Vec<_>>();
        self.root = self.build_compressed_subtree(0, &leaves);
    }

    fn build_compressed_subtree(
        &mut self,
        depth: usize,
        leaves: &[([u8; 32], H::Digest)],
    ) -> H::Digest {
        debug_assert!(!leaves.is_empty());

        if leaves.len() == 1 {
            let (key, leaf_hash) = &leaves[0];
            if depth == self.depth {
                self.nodes
                    .insert(NodeKey::leaf(*key), NodeEntry::Leaf(leaf_hash.clone()));
                self.last_node_accesses += 1;
                return leaf_hash.clone();
            }

            let shortcut_hash =
                Self::single_leaf_subtree_root(key, leaf_hash.clone(), depth, &self.empty_hashes);
            self.nodes.insert(
                NodeKey::new(*key, depth),
                NodeEntry::Shortcut {
                    prefix: u8::try_from(depth).expect("shortcut depth is less than 256"),
                    hash: shortcut_hash.clone(),
                },
            );
            self.last_node_accesses += 1;

            return shortcut_hash;
        }

        let mut left = Vec::new();
        let mut right = Vec::new();
        for (key, hash) in leaves {
            if bit_at(key, depth) {
                right.push((*key, hash.clone()));
            } else {
                left.push((*key, hash.clone()));
            }
        }

        let child_depth = depth + 1;
        let left_hash = if left.is_empty() {
            self.empty_hashes[self.depth - child_depth].clone()
        } else {
            self.build_compressed_subtree(child_depth, &left)
        };
        let right_hash = if right.is_empty() {
            self.empty_hashes[self.depth - child_depth].clone()
        } else {
            self.build_compressed_subtree(child_depth, &right)
        };
        let node_hash = H::hash_nodes(&left_hash, &right_hash);

        self.nodes.insert(
            NodeKey::new(leaves[0].0, depth),
            NodeEntry::Internal(node_hash.clone()),
        );
        self.last_node_accesses += 1;

        node_hash
    }

    fn single_leaf_subtree_root(
        key: &[u8; 32],
        leaf_hash: H::Digest,
        depth: usize,
        empty_hashes: &[H::Digest],
    ) -> H::Digest {
        let mut current = leaf_hash;

        for path_depth in (depth + 1..=SPARSE_TREE_DEPTH).rev() {
            let sibling = &empty_hashes[SPARSE_TREE_DEPTH - path_depth];
            current = if bit_at(key, path_depth - 1) {
                H::hash_nodes(sibling, &current)
            } else {
                H::hash_nodes(&current, sibling)
            };
        }

        current
    }

    fn subtree_hash_at(&self, node_key: NodeKey) -> Option<H::Digest> {
        let leaves = self
            .leaves
            .iter()
            .filter(|(key, _)| NodeKey::new(**key, node_key.depth) == node_key)
            .map(|(key, hash)| (*key, hash.clone()))
            .collect::<Vec<_>>();

        Self::subtree_root_from_leaves(node_key.depth, &leaves, &self.empty_hashes)
    }

    fn subtree_root_from_leaves(
        depth: usize,
        leaves: &[([u8; 32], H::Digest)],
        empty_hashes: &[H::Digest],
    ) -> Option<H::Digest> {
        match leaves {
            [] => None,
            [(key, leaf_hash)] => Some(Self::single_leaf_subtree_root(
                key,
                leaf_hash.clone(),
                depth,
                empty_hashes,
            )),
            _ => {
                let mut left = Vec::new();
                let mut right = Vec::new();
                for (key, hash) in leaves {
                    if bit_at(key, depth) {
                        right.push((*key, hash.clone()));
                    } else {
                        left.push((*key, hash.clone()));
                    }
                }

                let child_depth = depth + 1;
                let left_hash = Self::subtree_root_from_leaves(child_depth, &left, empty_hashes)
                    .unwrap_or_else(|| empty_hashes[SPARSE_TREE_DEPTH - child_depth].clone());
                let right_hash = Self::subtree_root_from_leaves(child_depth, &right, empty_hashes)
                    .unwrap_or_else(|| empty_hashes[SPARSE_TREE_DEPTH - child_depth].clone());

                Some(H::hash_nodes(&left_hash, &right_hash))
            }
        }
    }

    fn reconstruct_root(
        key: &[u8; 32],
        leaf_hash: H::Digest,
        siblings: &[Option<H::Digest>],
    ) -> H::Digest {
        let mut current = leaf_hash;
        let mut empty_hash = H::empty();
        let mut empty_level = 0_usize;

        for (level, sibling) in siblings.iter().enumerate() {
            let sibling_hash = sibling.as_ref().unwrap_or_else(|| {
                while empty_level < level {
                    empty_hash = H::hash_nodes(&empty_hash, &empty_hash);
                    empty_level += 1;
                }
                &empty_hash
            });
            let key_depth = SPARSE_TREE_DEPTH - 1 - level;

            current = if bit_at(key, key_depth) {
                H::hash_nodes(sibling_hash, &current)
            } else {
                H::hash_nodes(&current, sibling_hash)
            };
        }

        current
    }

    fn reconstruct_root(
        key: &[u8; 32],
        leaf_hash: H::Digest,
        siblings: &[Option<H::Digest>],
    ) -> H::Digest {
        let mut current = leaf_hash;
        let mut empty_hash = H::empty();
        let mut empty_level = 0_usize;

        for (level, sibling) in siblings.iter().enumerate() {
            let sibling_hash = sibling.as_ref().unwrap_or_else(|| {
                while empty_level < level {
                    empty_hash = H::hash_nodes(&empty_hash, &empty_hash);
                    empty_level += 1;
                }
                &empty_hash
            });
            let key_depth = SPARSE_TREE_DEPTH - 1 - level;

            current = if bit_at(key, key_depth) {
                H::hash_nodes(sibling_hash, &current)
            } else {
                H::hash_nodes(&current, sibling_hash)
            };
        }

        current
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
    use merkle_core::{error::MerkleError, traits::HashFunction, traits::Serializable};
    use merkleforge_hash::Sha256;

    use super::{
        EMPTY_HASH_LEVELS, NodeEntry, NodeKey, SPARSE_TREE_DEPTH, SparseMerkleTree, bit_at,
    };

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

    #[test]
    fn membership_proof_for_inserted_key_verifies() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [10_u8; 32];

        tree.insert(key, b"alice").unwrap();
        let proof = tree.generate_membership_proof(key).unwrap();
        let root = *tree.root().unwrap();

        assert_eq!(proof.key, key);
        assert_eq!(proof.siblings.len(), SPARSE_TREE_DEPTH);
        assert_eq!(proof.leaf, Some(Sha256::hash(b"alice")));
        assert!(SparseMerkleTree::<Sha256>::verify(&root, b"alice", &proof));
    }

    #[test]
    fn membership_proof_with_wrong_value_fails() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [11_u8; 32];

        tree.insert(key, b"alice").unwrap();
        let proof = tree.generate_membership_proof(key).unwrap();
        let root = *tree.root().unwrap();

        assert!(!SparseMerkleTree::<Sha256>::verify(
            &root, b"mallory", &proof
        ));
    }

    #[test]
    fn membership_proof_with_tampered_sibling_fails() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let first = [12_u8; 32];
        let mut second = [12_u8; 32];
        second[31] ^= 1;

        tree.insert(first, b"alice").unwrap();
        tree.insert(second, b"bob").unwrap();

        let mut proof = tree.generate_membership_proof(first).unwrap();
        let sibling = proof
            .siblings
            .iter_mut()
            .find_map(Option::as_mut)
            .expect("proof should include a non-empty sibling");
        sibling[0] ^= 1;

        let root = *tree.root().unwrap();
        assert!(!SparseMerkleTree::<Sha256>::verify(&root, b"alice", &proof));
    }

    #[test]
    fn proof_for_missing_key_records_non_membership_leaf() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let inserted = [13_u8; 32];
        let missing = [14_u8; 32];

        tree.insert(inserted, b"alice").unwrap();
        let proof = tree.generate_membership_proof(missing).unwrap();

        assert_eq!(proof.key, missing);
        assert_eq!(proof.siblings.len(), SPARSE_TREE_DEPTH);
        assert_eq!(proof.leaf, None);
        assert!(!proof.is_membership());
        assert!(proof.is_non_membership());
    }

    #[test]
    fn sparse_membership_proof_round_trips_through_serializable() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [15_u8; 32];

        tree.insert(key, b"alice").unwrap();
        let proof = tree.generate_membership_proof(key).unwrap();
        let bytes = proof.to_bytes().unwrap();
        let recovered = super::SparseMerkleProof::<[u8; 32]>::from_bytes(&bytes).unwrap();

        assert_eq!(proof, recovered);
    }

    #[test]
    fn non_membership_proof_for_never_inserted_key_verifies() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let inserted = [16_u8; 32];
        let missing = [17_u8; 32];

        tree.insert(inserted, b"alice").unwrap();
        let proof = tree.generate_membership_proof(missing).unwrap();
        let root = *tree.root().unwrap();

        assert!(SparseMerkleTree::<Sha256>::verify_non_membership(
            &root, missing, &proof
        ));
    }

    #[test]
    fn old_non_membership_proof_fails_after_key_is_inserted() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [18_u8; 32];

        let proof = tree.generate_membership_proof(key).unwrap();
        tree.insert(key, b"alice").unwrap();
        let root = *tree.root().unwrap();

        assert!(!SparseMerkleTree::<Sha256>::verify_non_membership(
            &root, key, &proof
        ));
    }

    #[test]
    fn non_membership_proof_verifies_after_key_is_removed() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [19_u8; 32];
        let other = [20_u8; 32];

        tree.insert(key, b"alice").unwrap();
        tree.insert(other, b"bob").unwrap();
        tree.remove(key).unwrap();

        let proof = tree.generate_membership_proof(key).unwrap();
        let root = *tree.root().unwrap();

        assert!(SparseMerkleTree::<Sha256>::verify_non_membership(
            &root, key, &proof
        ));
    }

    #[test]
    fn tampered_non_membership_proof_fails() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let inserted = [21_u8; 32];
        let mut missing = [21_u8; 32];
        missing[31] ^= 1;

        tree.insert(inserted, b"alice").unwrap();
        let mut proof = tree.generate_membership_proof(missing).unwrap();
        let sibling = proof
            .siblings
            .iter_mut()
            .find_map(Option::as_mut)
            .expect("proof should include a non-empty sibling");
        sibling[0] ^= 1;
        let root = *tree.root().unwrap();

        assert!(!SparseMerkleTree::<Sha256>::verify_non_membership(
            &root, missing, &proof
        ));
    }

    #[test]
    fn non_membership_verification_rejects_key_mismatch() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let inserted = [22_u8; 32];
        let missing = [23_u8; 32];
        let wrong_key = [24_u8; 32];

        tree.insert(inserted, b"alice").unwrap();
        let proof = tree.generate_membership_proof(missing).unwrap();
        let root = *tree.root().unwrap();

        assert!(!SparseMerkleTree::<Sha256>::verify_non_membership(
            &root, wrong_key, &proof
        ));
    }

    #[test]
    fn first_insert_materializes_one_shortcut_node() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let key = [25_u8; 32];

        tree.insert(key, b"alice").unwrap();

        assert_eq!(tree.stored_node_count(), 1);
        assert_eq!(tree.last_node_access_count(), 1);
        assert!(matches!(
            tree.nodes.get(&NodeKey::new(key, 0)),
            Some(NodeEntry::Shortcut { prefix: 0, .. })
        ));
    }

    #[test]
    fn sparse_inserts_touch_far_fewer_than_full_depth() {
        let mut tree = SparseMerkleTree::<Sha256>::new();

        for index in 0_u8..10 {
            let mut key = [0_u8; 32];
            key[0] = index << 4;
            tree.insert(key, &[index + 1]).unwrap();

            assert!(
                tree.last_node_access_count() < SPARSE_TREE_DEPTH,
                "insert {index} touched {} nodes",
                tree.last_node_access_count()
            );
        }

        assert_eq!(tree.leaf_count(), 10);
        assert!(tree.stored_node_count() < SPARSE_TREE_DEPTH);
    }

    #[test]
    fn membership_proofs_still_verify_with_shortcuts() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let mut keys = Vec::new();

        for index in 0_u8..10 {
            let mut key = [0_u8; 32];
            key[0] = index << 4;
            tree.insert(key, &[index + 1]).unwrap();
            keys.push((key, vec![index + 1]));
        }

        let root = *tree.root().unwrap();
        for (key, value) in keys {
            let proof = tree.generate_membership_proof(key).unwrap();
            assert!(SparseMerkleTree::<Sha256>::verify(&root, &value, &proof));
        }
    }

    #[test]
    fn non_membership_proofs_still_verify_with_shortcuts() {
        let mut tree = SparseMerkleTree::<Sha256>::new();

        for index in 0_u8..10 {
            let mut key = [0_u8; 32];
            key[0] = index << 4;
            tree.insert(key, &[index + 1]).unwrap();
        }

        let missing = [0xFF_u8; 32];
        let proof = tree.generate_membership_proof(missing).unwrap();
        let root = *tree.root().unwrap();

        assert!(SparseMerkleTree::<Sha256>::verify_non_membership(
            &root, missing, &proof
        ));
    }

    #[test]
    fn remove_recollapses_subtree_to_shortcut() {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let first = [0x10_u8; 32];
        let second = [0x90_u8; 32];

        tree.insert(first, b"alice").unwrap();
        tree.insert(second, b"bob").unwrap();
        assert!(tree.stored_node_count() > 1);

        tree.remove(second).unwrap();

        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.stored_node_count(), 1);
        assert!(matches!(
            tree.nodes.get(&NodeKey::new(first, 0)),
            Some(NodeEntry::Shortcut { prefix: 0, .. })
        ));

        let root = *tree.root().unwrap();
        let proof = tree.generate_membership_proof(first).unwrap();
        assert!(SparseMerkleTree::<Sha256>::verify(&root, b"alice", &proof));
    }
}
