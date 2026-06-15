use merkle_core::{
    traits::Serializable,
    types::{LeafIndex, MerkleProof},
};
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;
use proptest::{collection::vec, prelude::*, test_runner::TestCaseError};
use std::fmt::Display;

fn non_empty_leaves(range: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Vec<u8>>> {
    vec(vec(any::<u8>(), 1..64), range)
}

fn case_result<T, E: Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn required_root(tree: &BinaryMerkleTree<Sha256>) -> Result<[u8; 32], TestCaseError> {
    tree.root()
        .copied()
        .ok_or_else(|| TestCaseError::fail("non-empty tree did not have a root"))
}

fn build_tree(leaves: &[Vec<u8>]) -> Result<BinaryMerkleTree<Sha256>, TestCaseError> {
    let mut tree = BinaryMerkleTree::new();
    for leaf in leaves {
        case_result(tree.insert(leaf))?;
    }
    Ok(tree)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn root_changes_on_single_bit_leaf_mutation(
        leaves in non_empty_leaves(1..32),
        selected_leaf in any::<usize>(),
        selected_byte in any::<usize>(),
        selected_bit in 0u8..8,
    ) {
        let original_tree = build_tree(&leaves)?;
        let original_root = required_root(&original_tree)?;

        let mut mutated_leaves = leaves;
        let leaf_index = selected_leaf % mutated_leaves.len();
        let byte_index = selected_byte % mutated_leaves[leaf_index].len();
        mutated_leaves[leaf_index][byte_index] ^= 1 << selected_bit;

        let mutated_tree = build_tree(&mutated_leaves)?;
        let mutated_root = required_root(&mutated_tree)?;

        prop_assert_ne!(original_root, mutated_root);
    }

    #[test]
    fn proof_generated_after_insert_verifies(
        leaves in non_empty_leaves(1..32),
    ) {
        let mut tree = BinaryMerkleTree::<Sha256>::new();

        for leaf in &leaves {
            let index = case_result(tree.insert(leaf))?;
            let proof = case_result(tree.generate_proof(index))?;
            let root = required_root(&tree)?;

            prop_assert!(BinaryMerkleTree::<Sha256>::verify(&root, leaf, &proof));
        }
    }

    #[test]
    fn changing_any_proof_sibling_byte_fails_verification(
        leaves in non_empty_leaves(2..32),
        selected_leaf in any::<usize>(),
        selected_node in any::<usize>(),
        selected_byte in any::<usize>(),
    ) {
        let tree = build_tree(&leaves)?;
        let leaf_index = selected_leaf % leaves.len();
        let mut proof = case_result(tree.generate_proof(LeafIndex(leaf_index)))?;
        let path_index = selected_node % proof.path.len();
        let byte_index = selected_byte % proof.path[path_index].hash.len();
        proof.path[path_index].hash[byte_index] ^= 1;
        let root = required_root(&tree)?;

        prop_assert!(!BinaryMerkleTree::<Sha256>::verify(
            &root,
            &leaves[leaf_index],
            &proof,
        ));
    }

    #[test]
    fn removing_leaf_invalidates_its_existing_proof(
        leaves in non_empty_leaves(2..32),
        selected_leaf in any::<usize>(),
    ) {
        let mut tree = build_tree(&leaves)?;
        let leaf_index = selected_leaf % leaves.len();
        let proof = case_result(tree.generate_proof(LeafIndex(leaf_index)))?;

        case_result(tree.remove(LeafIndex(leaf_index)))?;
        let root = required_root(&tree)?;

        prop_assert!(!BinaryMerkleTree::<Sha256>::verify(
            &root,
            &leaves[leaf_index],
            &proof,
        ));
    }

    #[test]
    fn proofs_verify_for_every_valid_leaf_index(
        leaves in non_empty_leaves(1..32),
    ) {
        let tree = build_tree(&leaves)?;
        let root = required_root(&tree)?;

        for (index, leaf) in leaves.iter().enumerate() {
            let proof = case_result(tree.generate_proof(LeafIndex(index)))?;
            prop_assert!(BinaryMerkleTree::<Sha256>::verify(&root, leaf, &proof));
        }
    }

    #[test]
    fn serialized_proof_verifies_like_original(
        leaves in non_empty_leaves(1..32),
        selected_leaf in any::<usize>(),
    ) {
        let tree = build_tree(&leaves)?;
        let leaf_index = selected_leaf % leaves.len();
        let proof = case_result(tree.generate_proof(LeafIndex(leaf_index)))?;
        let bytes = case_result(proof.to_bytes())?;
        let recovered = case_result(MerkleProof::<[u8; 32]>::from_bytes(&bytes))?;
        let root = required_root(&tree)?;

        let original_valid =
            BinaryMerkleTree::<Sha256>::verify(&root, &leaves[leaf_index], &proof);
        let recovered_valid =
            BinaryMerkleTree::<Sha256>::verify(&root, &leaves[leaf_index], &recovered);

        prop_assert!(original_valid);
        prop_assert_eq!(original_valid, recovered_valid);
        prop_assert_eq!(proof, recovered);
    }
}
