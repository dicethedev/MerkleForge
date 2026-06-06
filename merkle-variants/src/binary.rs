//! Binary Merkle tree implementation.

use merkle_core::traits::HashFunction;

/// A cache-friendly binary Merkle tree backed by a flat node array.
///
/// Leaf nodes occupy the first power-of-two-sized layer. Each following
/// layer stores the parents of the previous layer, with the root at the final
/// array position.
pub struct BinaryMerkleTree<H: HashFunction> {
    nodes: Vec<H::Digest>,
    leaf_count: usize,
    height: usize,
}

impl<H: HashFunction> BinaryMerkleTree<H> {
    /// Creates an empty binary Merkle tree without preallocated leaf slots.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            leaf_count: 0,
            height: 0,
        }
    }

    /// Creates an empty tree with storage prepared for at least `capacity`
    /// leaves.
    ///
    /// The backing leaf layer is rounded up to the next power of two and
    /// initialized with [`HashFunction::empty`]. Reserving storage does not
    /// add logical leaves, so the returned tree remains empty.
    ///
    /// # Panics
    ///
    /// Panics if the requested capacity is too large to represent the flat
    /// node array.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        if capacity == 0 {
            return Self::new();
        }

        let padded_leaf_count = capacity
            .checked_next_power_of_two()
            .expect("binary Merkle tree capacity exceeds usize");
        let node_count = padded_leaf_count
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .expect("binary Merkle tree node count exceeds usize");
        let empty = H::empty();
        let mut nodes = vec![empty; node_count];

        Self::build_empty_internal_nodes(&mut nodes, padded_leaf_count);

        Self {
            nodes,
            leaf_count: 0,
            height: 0,
        }
    }

    /// Returns the current root digest, or `None` when no leaves are stored.
    #[must_use]
    pub fn root(&self) -> Option<&H::Digest> {
        if self.is_empty() {
            None
        } else {
            self.nodes.last()
        }
    }

    /// Returns the number of logical leaves currently stored.
    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns `true` when the tree contains no logical leaves.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    /// Returns the tree height, where an empty tree has height zero.
    #[must_use]
    pub const fn height(&self) -> usize {
        self.height
    }

    fn build_empty_internal_nodes(nodes: &mut [H::Digest], leaf_capacity: usize) {
        let mut layer_start = 0;
        let mut layer_width = leaf_capacity;
        let mut parent_start = leaf_capacity;

        while layer_width > 1 {
            for offset in 0..(layer_width / 2) {
                let left = nodes[layer_start + offset * 2].clone();
                let right = nodes[layer_start + offset * 2 + 1].clone();
                nodes[parent_start + offset] = H::hash_nodes(&left, &right);
            }

            layer_start = parent_start;
            layer_width /= 2;
            parent_start += layer_width;
        }
    }
}

impl<H: HashFunction> Default for BinaryMerkleTree<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkleforge_hash::Sha256;

    #[test]
    fn new_tree_is_empty() {
        let tree = BinaryMerkleTree::<Sha256>::new();

        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.root(), None);
        assert!(tree.nodes.is_empty());
    }

    #[test]
    fn zero_capacity_matches_new() {
        let tree = BinaryMerkleTree::<Sha256>::with_capacity(0);

        assert!(tree.is_empty());
        assert_eq!(tree.height(), 0);
        assert!(tree.nodes.is_empty());
    }

    #[test]
    fn capacity_is_padded_to_next_power_of_two() {
        let tree = BinaryMerkleTree::<Sha256>::with_capacity(3);

        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.root(), None);
        assert_eq!(tree.nodes.len(), 7);
        assert!(tree.nodes[..4].iter().all(|node| node == &Sha256::empty()));
    }

    #[test]
    fn empty_internal_nodes_are_built_bottom_up() {
        let tree = BinaryMerkleTree::<Sha256>::with_capacity(4);
        let empty = Sha256::empty();
        let parent = Sha256::hash_nodes(&empty, &empty);
        let expected_root = Sha256::hash_nodes(&parent, &parent);

        assert_eq!(tree.nodes[4], parent);
        assert_eq!(tree.nodes[5], parent);
        assert_eq!(tree.nodes[6], expected_root);
    }
}
