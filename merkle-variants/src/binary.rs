//! Binary Merkle tree implementation.

use merkle_core::{
    error::MerkleError,
    traits::{HashFunction, MerkleTree, ProofVerifier},
    types::{LeafIndex, MerkleProof, ProofNode, ProofSide, TreeMetadata},
};

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

        let leaf_capacity = Self::padded_leaf_count(capacity);
        let mut tree = Self {
            nodes: vec![H::empty(); Self::node_count(leaf_capacity)],
            leaf_count: 0,
            height: 0,
        };
        tree.recompute_root();
        tree
    }

    /// Inserts a non-empty leaf and returns its stable leaf index.
    ///
    /// The leaf layer grows to the next power of two when its current
    /// capacity is exhausted. Internal nodes are then recomputed iteratively
    /// from the leaf layer to the root.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::EmptyLeafData`] when `data` is empty.
    pub fn insert(&mut self, data: &[u8]) -> Result<LeafIndex, MerkleError> {
        if data.is_empty() {
            return Err(MerkleError::EmptyLeafData);
        }

        let index = LeafIndex(self.leaf_count);
        self.ensure_leaf_capacity(self.leaf_count + 1);
        self.nodes[index.value()] = H::hash(data);
        self.leaf_count += 1;
        self.height = self.leaf_capacity().ilog2() as usize + 1;
        self.recompute_root();

        Ok(index)
    }

    /// Removes a leaf by replacing it with [`HashFunction::empty`].
    ///
    /// Removing trailing leaves also reduces the logical leaf count and may
    /// shrink the padded tree. Interior removals preserve all later indices.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::IndexOutOfBounds`] when `index` does not refer
    /// to a logical leaf.
    pub fn remove(&mut self, index: LeafIndex) -> Result<(), MerkleError> {
        if index.value() >= self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds {
                index: index.value(),
                len: self.leaf_count,
            });
        }

        self.nodes[index.value()] = H::empty();
        self.trim_empty_trailing_leaves();

        if self.leaf_count == 0 {
            self.height = 0;
            self.recompute_root();
            return Ok(());
        }

        let required_capacity = Self::padded_leaf_count(self.leaf_count);
        if required_capacity < self.leaf_capacity() {
            self.resize_leaf_layer(required_capacity);
        } else {
            self.recompute_root();
        }
        self.height = required_capacity.ilog2() as usize + 1;

        Ok(())
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

    /// Generates an inclusion proof for the leaf at `index`.
    ///
    /// Sibling hashes are collected from the leaf layer upward. Each proof
    /// node records whether the sibling belongs on the left or right when
    /// reconstructing the root.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::EmptyTree`] when the tree has no logical leaves.
    /// Returns [`MerkleError::IndexOutOfBounds`] when `index` is not a logical
    /// leaf index.
    pub fn generate_proof(&self, index: LeafIndex) -> Result<MerkleProof<H::Digest>, MerkleError> {
        if self.is_empty() {
            return Err(MerkleError::EmptyTree);
        }
        if index.value() >= self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds {
                index: index.value(),
                len: self.leaf_count,
            });
        }

        let mut path = Vec::with_capacity(self.height.saturating_sub(1));
        let mut layer_start = 0;
        let mut layer_width = self.leaf_capacity();
        let mut offset = index.value();

        while layer_width > 1 {
            let (sibling_offset, side) = if offset.is_multiple_of(2) {
                (offset + 1, ProofSide::Right)
            } else {
                (offset - 1, ProofSide::Left)
            };

            path.push(ProofNode {
                hash: self.nodes[layer_start + sibling_offset].clone(),
                side,
            });

            offset /= 2;
            layer_start += layer_width;
            layer_width /= 2;
        }

        Ok(MerkleProof {
            leaf_index: index,
            leaf_count: self.leaf_count,
            path,
        })
    }

    /// Verifies an inclusion proof without accessing a tree instance.
    ///
    /// Returns `false` when the proof structure is inconsistent with its
    /// claimed leaf index or leaf count.
    #[must_use]
    pub fn verify(
        expected_root: &H::Digest,
        leaf_data: &[u8],
        proof: &MerkleProof<H::Digest>,
    ) -> bool {
        <Self as ProofVerifier<H>>::verify(expected_root, leaf_data, proof)
    }

    const fn padded_leaf_count(leaf_count: usize) -> usize {
        leaf_count
            .checked_next_power_of_two()
            .expect("binary Merkle tree capacity exceeds usize")
    }

    fn node_count(leaf_capacity: usize) -> usize {
        leaf_capacity
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .expect("binary Merkle tree node count exceeds usize")
    }

    const fn leaf_capacity(&self) -> usize {
        self.nodes.len().div_ceil(2)
    }

    fn ensure_leaf_capacity(&mut self, required: usize) {
        if required > self.leaf_capacity() {
            self.resize_leaf_layer(Self::padded_leaf_count(required));
        }
    }

    fn resize_leaf_layer(&mut self, new_capacity: usize) {
        let leaves_to_copy = self.leaf_count.min(new_capacity);
        let mut nodes = vec![H::empty(); Self::node_count(new_capacity)];

        if leaves_to_copy > 0 {
            nodes[..leaves_to_copy].clone_from_slice(&self.nodes[..leaves_to_copy]);
        }

        self.nodes = nodes;
        self.recompute_root();
    }

    fn trim_empty_trailing_leaves(&mut self) {
        let empty = H::empty();
        while self.leaf_count > 0 && self.nodes[self.leaf_count - 1] == empty {
            self.leaf_count -= 1;
        }
    }

    fn recompute_root(&mut self) {
        let leaf_capacity = self.leaf_capacity();
        if leaf_capacity == 0 {
            return;
        }

        let mut layer_start = 0;
        let mut layer_width = leaf_capacity;
        let mut parent_start = leaf_capacity;

        while layer_width > 1 {
            for offset in 0..(layer_width / 2) {
                let left = self.nodes[layer_start + offset * 2].clone();
                let right = self.nodes[layer_start + offset * 2 + 1].clone();
                self.nodes[parent_start + offset] = H::hash_nodes(&left, &right);
            }

            layer_start = parent_start;
            layer_width /= 2;
            parent_start += layer_width;
        }
    }
}

impl<H: HashFunction> MerkleTree<H> for BinaryMerkleTree<H> {
    fn insert(&mut self, data: &[u8]) -> Result<LeafIndex, MerkleError> {
        Self::insert(self, data)
    }

    fn remove(&mut self, index: LeafIndex) -> Result<(), MerkleError> {
        Self::remove(self, index)
    }

    fn root(&self) -> Option<&H::Digest> {
        Self::root(self)
    }

    fn leaf_count(&self) -> usize {
        Self::leaf_count(self)
    }

    fn is_empty(&self) -> bool {
        Self::is_empty(self)
    }

    fn height(&self) -> usize {
        Self::height(self)
    }

    fn generate_proof(&self, index: LeafIndex) -> Result<MerkleProof<H::Digest>, MerkleError> {
        Self::generate_proof(self, index)
    }

    fn metadata(&self) -> TreeMetadata {
        TreeMetadata {
            leaf_count: self.leaf_count,
            height: self.height,
            node_count: self.nodes.len(),
            hash_algorithm: H::algorithm_name(),
            variant: "BinaryMerkleTree",
        }
    }
}

impl<H: HashFunction> ProofVerifier<H> for BinaryMerkleTree<H> {
    fn verify(expected_root: &H::Digest, leaf_data: &[u8], proof: &MerkleProof<H::Digest>) -> bool {
        if leaf_data.is_empty()
            || proof.leaf_count == 0
            || proof.leaf_index.value() >= proof.leaf_count
        {
            return false;
        }

        let Some(leaf_capacity) = proof.leaf_count.checked_next_power_of_two() else {
            return false;
        };
        let expected_depth = leaf_capacity.ilog2() as usize;
        if proof.path.len() != expected_depth {
            return false;
        }

        let mut current = H::hash(leaf_data);
        let mut offset = proof.leaf_index.value();

        for node in &proof.path {
            let expected_side = if offset.is_multiple_of(2) {
                ProofSide::Right
            } else {
                ProofSide::Left
            };
            if node.side != expected_side {
                return false;
            }

            current = match node.side {
                ProofSide::Left => H::hash_nodes(&node.hash, &current),
                ProofSide::Right => H::hash_nodes(&current, &node.hash),
            };
            offset /= 2;
        }

        current == *expected_root
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

    #[test]
    fn inserting_one_leaf_produces_root() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        let index = tree.insert(b"alice").unwrap();

        assert_eq!(index, LeafIndex(0));
        assert_eq!(tree.root(), Some(&Sha256::hash(b"alice")));
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.height(), 1);
        assert!(!tree.is_empty());
    }

    #[test]
    fn insertion_resizes_and_recomputes_root() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();
        tree.insert(b"bob").unwrap();
        tree.insert(b"carol").unwrap();

        let alice = Sha256::hash(b"alice");
        let bob = Sha256::hash(b"bob");
        let carol = Sha256::hash(b"carol");
        let left = Sha256::hash_nodes(&alice, &bob);
        let right = Sha256::hash_nodes(&carol, &Sha256::empty());
        let expected = Sha256::hash_nodes(&left, &right);

        assert_eq!(tree.root(), Some(&expected));
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.height(), 3);
        assert_eq!(tree.nodes.len(), 7);
    }

    #[test]
    fn empty_leaf_data_is_rejected() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();

        assert_eq!(tree.insert(b""), Err(MerkleError::EmptyLeafData));
        assert!(tree.is_empty());
    }

    #[test]
    fn removing_only_leaf_returns_tree_to_empty_state() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        let index = tree.insert(b"alice").unwrap();
        tree.remove(index).unwrap();

        assert!(tree.is_empty());
        assert_eq!(tree.root(), None);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.nodes[0], Sha256::empty());
    }

    #[test]
    fn removing_interior_leaf_preserves_later_indices() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();
        tree.insert(b"bob").unwrap();
        tree.insert(b"carol").unwrap();
        tree.remove(LeafIndex(1)).unwrap();

        let alice = Sha256::hash(b"alice");
        let carol = Sha256::hash(b"carol");
        let left = Sha256::hash_nodes(&alice, &Sha256::empty());
        let right = Sha256::hash_nodes(&carol, &Sha256::empty());
        let expected = Sha256::hash_nodes(&left, &right);

        assert_eq!(tree.root(), Some(&expected));
        assert_eq!(tree.leaf_count(), 3);
    }

    #[test]
    fn removing_trailing_leaf_shrinks_tree() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();
        tree.insert(b"bob").unwrap();
        tree.remove(LeafIndex(1)).unwrap();

        assert_eq!(tree.root(), Some(&Sha256::hash(b"alice")));
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.height(), 1);
        assert_eq!(tree.nodes.len(), 1);
    }

    #[test]
    fn out_of_bounds_remove_is_rejected() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();

        assert_eq!(
            tree.remove(LeafIndex(0)),
            Err(MerkleError::IndexOutOfBounds { index: 0, len: 0 })
        );
    }

    #[test]
    fn trait_methods_delegate_to_binary_tree() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        let index =
            <BinaryMerkleTree<Sha256> as MerkleTree<Sha256>>::insert(&mut tree, b"trait leaf")
                .unwrap();

        assert_eq!(index, LeafIndex(0));
        assert!(<BinaryMerkleTree<Sha256> as MerkleTree<Sha256>>::root(&tree).is_some());

        let metadata = tree.metadata();
        assert_eq!(metadata.leaf_count, 1);
        assert_eq!(metadata.height, 1);
        assert_eq!(metadata.node_count, 1);
        assert_eq!(metadata.hash_algorithm, "SHA-256");
        assert_eq!(metadata.variant, "BinaryMerkleTree");
    }

    #[test]
    fn proof_generation_rejects_empty_tree() {
        let tree = BinaryMerkleTree::<Sha256>::new();

        assert_eq!(
            tree.generate_proof(LeafIndex(0)),
            Err(MerkleError::EmptyTree)
        );
    }

    #[test]
    fn proof_generation_rejects_out_of_bounds_index() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();

        assert_eq!(
            tree.generate_proof(LeafIndex(1)),
            Err(MerkleError::IndexOutOfBounds { index: 1, len: 1 })
        );
    }

    #[test]
    fn single_leaf_proof_is_trivial() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();

        let proof = tree.generate_proof(LeafIndex(0)).unwrap();

        assert!(proof.is_trivial());
        assert_eq!(proof.depth(), 0);
        assert_eq!(proof.leaf_index, LeafIndex(0));
        assert_eq!(proof.leaf_count, 1);
    }

    #[test]
    fn proof_path_has_one_node_per_non_leaf_level() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        for data in [b"alice".as_slice(), b"bob", b"carol"] {
            tree.insert(data).unwrap();
        }

        for index in 0..tree.leaf_count() {
            let proof = tree.generate_proof(LeafIndex(index)).unwrap();
            assert_eq!(proof.depth(), tree.height() - 1);
        }
    }

    #[test]
    fn proof_records_correct_siblings_and_sides() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        for data in [b"alice".as_slice(), b"bob", b"carol", b"dave"] {
            tree.insert(data).unwrap();
        }

        let alice = Sha256::hash(b"alice");
        let bob = Sha256::hash(b"bob");
        let carol = Sha256::hash(b"carol");
        let dave = Sha256::hash(b"dave");
        let left_parent = Sha256::hash_nodes(&alice, &bob);
        let right_parent = Sha256::hash_nodes(&carol, &dave);

        let left_proof = tree.generate_proof(LeafIndex(0)).unwrap();
        assert_eq!(
            left_proof.path,
            vec![
                ProofNode {
                    hash: bob,
                    side: ProofSide::Right,
                },
                ProofNode {
                    hash: right_parent,
                    side: ProofSide::Right,
                },
            ]
        );

        let right_proof = tree.generate_proof(LeafIndex(3)).unwrap();
        assert_eq!(
            right_proof.path,
            vec![
                ProofNode {
                    hash: carol,
                    side: ProofSide::Left,
                },
                ProofNode {
                    hash: left_parent,
                    side: ProofSide::Left,
                },
            ]
        );
    }

    #[test]
    fn every_valid_index_produces_a_root_reconstructing_proof() {
        let data = [b"alice".as_slice(), b"bob", b"carol", b"dave", b"eve"];
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        for leaf in data {
            tree.insert(leaf).unwrap();
        }

        for (index, leaf) in data.iter().enumerate() {
            let proof = tree.generate_proof(LeafIndex(index)).unwrap();
            let reconstructed =
                proof
                    .path
                    .iter()
                    .fold(Sha256::hash(leaf), |current, node| match node.side {
                        ProofSide::Left => Sha256::hash_nodes(&node.hash, &current),
                        ProofSide::Right => Sha256::hash_nodes(&current, &node.hash),
                    });

            assert_eq!(Some(&reconstructed), tree.root());
        }
    }

    #[test]
    fn valid_proof_verifies() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        for data in [b"alice".as_slice(), b"bob", b"carol"] {
            tree.insert(data).unwrap();
        }
        let proof = tree.generate_proof(LeafIndex(1)).unwrap();

        assert!(BinaryMerkleTree::<Sha256>::verify(
            tree.root().unwrap(),
            b"bob",
            &proof
        ));
    }

    #[test]
    fn wrong_leaf_data_fails_verification() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();
        tree.insert(b"bob").unwrap();
        let proof = tree.generate_proof(LeafIndex(0)).unwrap();

        assert!(!BinaryMerkleTree::<Sha256>::verify(
            tree.root().unwrap(),
            b"mallory",
            &proof
        ));
    }

    #[test]
    fn tampered_sibling_fails_verification() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();
        tree.insert(b"bob").unwrap();
        let mut proof = tree.generate_proof(LeafIndex(0)).unwrap();
        proof.path[0].hash = Sha256::hash(b"tampered");

        assert!(!BinaryMerkleTree::<Sha256>::verify(
            tree.root().unwrap(),
            b"alice",
            &proof
        ));
    }

    #[test]
    fn proof_from_different_tree_fails_verification() {
        let mut first = BinaryMerkleTree::<Sha256>::new();
        first.insert(b"alice").unwrap();
        first.insert(b"bob").unwrap();
        let proof = first.generate_proof(LeafIndex(0)).unwrap();

        let mut second = BinaryMerkleTree::<Sha256>::new();
        second.insert(b"alice").unwrap();
        second.insert(b"carol").unwrap();

        assert!(!BinaryMerkleTree::<Sha256>::verify(
            second.root().unwrap(),
            b"alice",
            &proof
        ));
    }

    #[test]
    fn trivial_proof_verifies() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();
        let proof = tree.generate_proof(LeafIndex(0)).unwrap();

        assert!(proof.is_trivial());
        assert!(BinaryMerkleTree::<Sha256>::verify(
            tree.root().unwrap(),
            b"alice",
            &proof
        ));
    }

    #[test]
    fn invalid_proof_index_returns_false() {
        let proof = MerkleProof {
            leaf_index: LeafIndex(1),
            leaf_count: 1,
            path: Vec::new(),
        };

        assert!(!BinaryMerkleTree::<Sha256>::verify(
            &Sha256::hash(b"alice"),
            b"alice",
            &proof
        ));
    }

    #[test]
    fn invalid_path_length_returns_false() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();
        tree.insert(b"bob").unwrap();
        let mut proof = tree.generate_proof(LeafIndex(0)).unwrap();
        proof.path.clear();

        assert!(!BinaryMerkleTree::<Sha256>::verify(
            tree.root().unwrap(),
            b"alice",
            &proof
        ));
    }

    #[test]
    fn invalid_sibling_side_returns_false() {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"alice").unwrap();
        tree.insert(b"bob").unwrap();
        let mut proof = tree.generate_proof(LeafIndex(0)).unwrap();
        proof.path[0].side = ProofSide::Left;

        assert!(!BinaryMerkleTree::<Sha256>::verify(
            tree.root().unwrap(),
            b"alice",
            &proof
        ));
    }
}
