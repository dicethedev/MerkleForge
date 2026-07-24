//! Merkle Patricia trie implementation.
//!
//! [`MerklePatriciaTrie`] models Ethereum's nibble-addressed Merkle Patricia
//! Trie shape. This module currently defines the core node structure,
//! nibble-path utilities, and empty-trie metadata. Mutation, RLP encoding, and
//! root hashing are added in later Phase 4 issues.

use std::marker::PhantomData;

use merkle_core::traits::HashFunction;

/// A sequence of 4-bit nibbles extracted from a byte key.
///
/// Each stored nibble is guaranteed to be in the range `0x0..=0xF` when
/// constructed through [`Self::from_key`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NibblePath {
    nibbles: Vec<u8>,
}

impl NibblePath {
    /// Converts a byte key into a high-nibble-first path.
    ///
    /// Every input byte contributes two nibbles. For example, `b"key"` has
    /// three bytes and therefore produces six nibbles.
    #[must_use]
    pub fn from_key(key: &[u8]) -> Self {
        let mut nibbles = Vec::with_capacity(key.len() * 2);
        for byte in key {
            nibbles.push(byte >> 4);
            nibbles.push(byte & 0x0F);
        }

        Self { nibbles }
    }

    /// Returns the number of nibbles in this path.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nibbles.len()
    }

    /// Returns `true` when this path contains no nibbles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nibbles.is_empty()
    }

    /// Returns the nibble at `idx`.
    ///
    /// # Panics
    ///
    /// Panics when `idx` is outside this path.
    #[must_use]
    pub fn get(&self, idx: usize) -> u8 {
        self.nibbles[idx]
    }

    /// Returns a path beginning at nibble `start`.
    ///
    /// # Panics
    ///
    /// Panics when `start` is greater than [`Self::len`].
    #[must_use]
    pub fn slice(&self, start: usize) -> Self {
        Self {
            nibbles: self.nibbles[start..].to_vec(),
        }
    }

    /// Returns the shared prefix length with `other`, measured in nibbles.
    #[must_use]
    pub fn common_prefix_len(&self, other: &Self) -> usize {
        self.nibbles
            .iter()
            .zip(&other.nibbles)
            .take_while(|(left, right)| left == right)
            .count()
    }
}

/// A Merkle Patricia Trie node.
///
/// The public variants mirror Ethereum's four logical MPT node types: empty,
/// leaf, extension, and branch. The hidden marker variant exists only to make
/// the digest type parameter available before later issues add node hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MptNode<D> {
    /// Empty slot with no data at this path.
    Empty,

    /// Leaf node storing the remaining key suffix and value bytes.
    Leaf {
        /// Remaining nibble path after the branch point.
        key_suffix: NibblePath,
        /// Value stored at the complete key.
        value: Vec<u8>,
    },

    /// Extension node compressing a shared nibble prefix.
    Extension {
        /// Shared prefix consumed before following `child`.
        shared_prefix: NibblePath,
        /// Next trie node after the compressed prefix.
        child: Box<MptNode<D>>,
    },

    /// Branch node with one child slot per nibble plus an optional value.
    Branch {
        /// Children indexed by nibble `0x0..=0xF`.
        children: [Box<MptNode<D>>; 16],
        /// Value stored exactly at this branch path, if any.
        value: Option<Vec<u8>>,
    },

    #[doc(hidden)]
    __DigestMarker(PhantomData<D>),
}

impl<D> MptNode<D> {
    #[cfg(test)]
    fn empty_children() -> [Box<Self>; 16] {
        std::array::from_fn(|_| Box::new(Self::Empty))
    }

    fn height(&self) -> usize {
        match self {
            Self::Empty | Self::__DigestMarker(_) => 0,
            Self::Leaf { .. } => 1,
            Self::Extension { child, .. } => 1 + child.height(),
            Self::Branch { children, .. } => {
                1 + children
                    .iter()
                    .map(|child| child.height())
                    .max()
                    .unwrap_or(0)
            }
        }
    }
}

/// Ethereum-style Merkle Patricia Trie over nibble-addressed keys.
///
/// The trie starts empty. Later Phase 4 work will add mutation, RLP
/// serialization, and root hashing.
pub struct MerklePatriciaTrie<H: HashFunction> {
    root: MptNode<H::Digest>,
    node_count: usize,
    _marker: PhantomData<H>,
}

impl<H: HashFunction> MerklePatriciaTrie<H> {
    /// Creates an empty Merkle Patricia Trie.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root: MptNode::Empty,
            node_count: 0,
            _marker: PhantomData,
        }
    }

    /// Returns the current root digest, or `None` for an empty trie.
    ///
    /// Root hashing is introduced in a later Phase 4 issue, so the current
    /// structural skeleton reports no digest.
    #[must_use]
    pub const fn root(&self) -> Option<&H::Digest> {
        None
    }

    /// Returns `true` when the trie contains no materialized nodes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.node_count == 0
    }

    /// Returns the number of materialized trie nodes.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.node_count
    }

    /// Returns the longest node path from the root to any leaf.
    #[must_use]
    pub fn height(&self) -> usize {
        self.root.height()
    }
}

impl<H: HashFunction> Default for MerklePatriciaTrie<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use merkleforge_hash::Keccak256;

    use super::{MerklePatriciaTrie, MptNode, NibblePath};

    #[test]
    fn new_trie_is_empty() {
        let tree = MerklePatriciaTrie::<Keccak256>::new();

        assert!(tree.is_empty());
        assert_eq!(tree.root(), None);
        assert_eq!(tree.node_count(), 0);
        assert_eq!(tree.height(), 0);
    }

    #[test]
    fn nibble_path_from_key_splits_each_byte() {
        let path = NibblePath::from_key(b"key");

        assert_eq!(path.len(), 6);
        assert_eq!(path.get(0), 0x6);
        assert_eq!(path.get(1), 0xB);
        assert_eq!(path.get(2), 0x6);
        assert_eq!(path.get(3), 0x5);
        assert_eq!(path.get(4), 0x7);
        assert_eq!(path.get(5), 0x9);
    }

    #[test]
    fn nibble_path_slice_keeps_suffix() {
        let path = NibblePath::from_key(&[0xAB, 0xCD]);
        let suffix = path.slice(2);

        assert_eq!(suffix.len(), 2);
        assert_eq!(suffix.get(0), 0xC);
        assert_eq!(suffix.get(1), 0xD);
    }

    #[test]
    fn nibble_path_common_prefix_len_counts_matching_nibbles() {
        let first = NibblePath::from_key(&[0xAB, 0xCD]);
        let second = NibblePath::from_key(&[0xAB, 0xEF]);

        assert_eq!(first.common_prefix_len(&second), 2);
    }

    #[test]
    fn all_four_node_variants_compile() {
        let leaf = MptNode::<[u8; 32]>::Leaf {
            key_suffix: NibblePath::from_key(b"leaf"),
            value: b"value".to_vec(),
        };
        let extension = MptNode::<[u8; 32]>::Extension {
            shared_prefix: NibblePath::from_key(b"shared"),
            child: Box::new(MptNode::Empty),
        };
        let branch = MptNode::<[u8; 32]>::Branch {
            children: MptNode::empty_children(),
            value: Some(b"branch value".to_vec()),
        };

        assert!(matches!(MptNode::<[u8; 32]>::Empty, MptNode::Empty));
        assert!(matches!(leaf, MptNode::Leaf { .. }));
        assert!(matches!(extension, MptNode::Extension { .. }));
        assert!(matches!(branch, MptNode::Branch { .. }));
    }

    #[test]
    fn node_height_tracks_longest_path_to_leaf() {
        let node = MptNode::<[u8; 32]>::Extension {
            shared_prefix: NibblePath::from_key(&[0xA0]),
            child: Box::new(MptNode::Leaf {
                key_suffix: NibblePath::from_key(&[0xBC]),
                value: b"value".to_vec(),
            }),
        };

        assert_eq!(node.height(), 2);
    }
}
