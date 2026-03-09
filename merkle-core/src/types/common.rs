//! # merkle-core :: types :: common
//!
//! Newtype wrappers and plain data structs used across every tree variant.
//! Keeping them here avoids circular dependencies between `merkle-variants`
//! crates and lets `merkle-bench` import them without pulling in any
//! tree-specific logic.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── NodeIndex ──────────────────────────────────────────────────────────────
/// A strongly-typed index into the flat node array of a Merkle tree.
///
/// Nodes are numbered with 0 being the first *leaf*.  Internal nodes start
/// at index `leaf_count` and the root is the last element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeIndex(pub usize);

impl NodeIndex {
    /// The node index of the root of a tree with `leaf_count` leaves.
    ///
    /// For a power-of-two tree the root sits at index `2 * leaf_count - 1`.
    #[inline]
    pub fn root(leaf_count: usize) -> Self {
        debug_assert!(leaf_count > 0, "leaf_count must be positive");
        Self(2 * leaf_count - 1)
    }

    /// Returns the raw `usize` value.
    #[inline]
    pub fn value(self) -> usize {
        self.0
    }
}

impl fmt::Display for NodeIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeIndex({})", self.0)
    }
}

// ── LeafIndex ─────────────────────────────────────────────────────────────

/// A strongly-typed index into the *leaf* layer of a Merkle tree.
///
/// `LeafIndex(0)` is the leftmost leaf.  A `LeafIndex` can be converted to a
/// `NodeIndex` but not vice-versa — this prevents accidentally treating an
/// internal-node index as a leaf position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeafIndex(pub usize);

impl LeafIndex {
    /// Convert to the corresponding `NodeIndex` in the flat array layout.
    #[inline]
    pub fn to_node_index(self) -> NodeIndex {
        NodeIndex(self.0)
    }

    /// Returns the raw `usize` value.
    #[inline]
    pub fn value(self) -> usize {
        self.0
    }
}

impl fmt::Display for LeafIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LeafIndex({})", self.0)
    }
}

impl From<LeafIndex> for NodeIndex {
    fn from(li: LeafIndex) -> Self {
        li.to_node_index()
    }
}

// ── ProofSide ──────────────────────────────────────────────────────────────

/// Indicates which side a sibling sits on during proof path traversal.
///
/// When reconstructing the root from a proof, the verifier must know
/// whether each sibling is the *left* or *right* child of their shared
/// parent so it concatenates them in the correct order before hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSide {
    /// The proof sibling is the left child; the current hash is on the right.
    Left,
    /// The proof sibling is the right child; the current hash is on the left.
    Right,
}

// ── ProofNode ─────────────────────────────────────────────────────────────

/// A single step on the Merkle proof path: a sibling hash and the side it
/// sits on.
///
/// The type parameter `D` is the concrete digest type produced by the chosen
/// [`HashFunction`](crate::traits::HashFunction).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofNode<D> {
    /// The sibling hash at this level of the tree.
    pub hash: D,
    /// Whether the sibling is on the left or right.
    pub side: ProofSide,
}

// ── MerkleProof ───────────────────────────────────────────────────────────

/// A Merkle inclusion proof for a single leaf.
///
/// The proof consists of the sibling hashes along the path from the leaf to
/// the root.  A stateless verifier can reconstruct the root by:
///
/// 1. Hashing the leaf data → `current`.
/// 2. For each [`ProofNode`] in `path` (bottom-up):
///    - If `side == Left`: `current = H(sibling || current)`
///    - If `side == Right`: `current = H(current || sibling)`
/// 3. Comparing `current` to the known root.
///
/// Proofs are serialisable so they can be transmitted over a network or
/// stored in a database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof<D> {
    /// The index of the leaf this proof is for.
    pub leaf_index: LeafIndex,
    /// Total number of leaves in the tree at the time the proof was generated.
    pub leaf_count: usize,
    /// Sibling hashes from the leaf level up to (but not including) the root.
    pub path: Vec<ProofNode<D>>,
}

impl<D: fmt::Debug> MerkleProof<D> {
    /// Returns the depth of this proof, i.e. the number of hashing steps
    /// required to recompute the root.
    #[inline]
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Returns `true` if the proof path is empty (degenerate single-leaf tree).
    #[inline]
    pub fn is_trivial(&self) -> bool {
        self.path.is_empty()
    }
}

// ── TreeMetadata ──────────────────────────────────────────────────────────

/// Lightweight metadata snapshot about a tree's current state.
///
/// Useful for logging, diagnostics, and the benchmarking suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeMetadata {
    /// Number of leaves currently stored.
    pub leaf_count: usize,
    /// Height of the tree (0 for an empty tree, 1 for a single leaf).
    pub height: usize,
    /// Total number of nodes (leaves + internal nodes).
    pub node_count: usize,
    /// Name of the hash algorithm in use (e.g. `"SHA-256"`, `"BLAKE3"`).
    pub hash_algorithm: &'static str,
    /// Name of the tree variant (e.g. `"BinaryMerkleTree"`).
    pub variant: &'static str,
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_index_root_single_leaf() {
        assert_eq!(NodeIndex::root(1), NodeIndex(1));
    }

    #[test]
    fn node_index_root_four_leaves() {
        // flat array: [L0, L1, L2, L3, P01, P23, Root]
        // root index = 2*4 - 1 = 7
        assert_eq!(NodeIndex::root(4), NodeIndex(7));
    }

    #[test]
    fn leaf_index_to_node_index() {
        let li = LeafIndex(3);
        let ni: NodeIndex = li.into();
        assert_eq!(ni, NodeIndex(3));
    }

    #[test]
    fn proof_depth_and_trivial() {
        let trivial: MerkleProof<[u8; 32]> = MerkleProof {
            leaf_index: LeafIndex(0),
            leaf_count: 1,
            path: vec![],
        };
        assert!(trivial.is_trivial());
        assert_eq!(trivial.depth(), 0);

        let two_level: MerkleProof<[u8; 32]> = MerkleProof {
            leaf_index: LeafIndex(0),
            leaf_count: 4,
            path: vec![
                ProofNode {
                    hash: [0u8; 32],
                    side: ProofSide::Right,
                },
                ProofNode {
                    hash: [1u8; 32],
                    side: ProofSide::Right,
                },
            ],
        };
        assert!(!two_level.is_trivial());
        assert_eq!(two_level.depth(), 2);
    }
}
