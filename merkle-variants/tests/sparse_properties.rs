use std::{collections::BTreeSet, fmt::Display};

use merkle_core::traits::Serializable;
use merkle_variants::{
    SparseMerkleTree,
    sparse::{SPARSE_TREE_DEPTH, SparseMerkleProof},
};
use merkleforge_hash::Sha256;
use proptest::{collection::vec, prelude::*, test_runner::TestCaseError};

type Key = [u8; 32];
type Update = (Key, Vec<u8>);

fn values(range: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), range)
}

fn updates(range: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Update>> {
    vec((prop::array::uniform32(any::<u8>()), values(1..64)), range)
}

fn case_result<T, E: Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn required_root(tree: &SparseMerkleTree<Sha256>) -> Result<[u8; 32], TestCaseError> {
    tree.root()
        .copied()
        .ok_or_else(|| TestCaseError::fail("non-empty sparse tree did not have a root"))
}

fn build_tree(updates: &[Update]) -> Result<SparseMerkleTree<Sha256>, TestCaseError> {
    let mut tree = SparseMerkleTree::new();
    for (key, value) in updates {
        case_result(tree.insert(*key, value))?;
    }
    Ok(tree)
}

fn absent_key(seed: Key, present: &[Update]) -> Key {
    let keys = present.iter().map(|(key, _)| *key).collect::<BTreeSet<_>>();
    let mut candidate = seed;

    while keys.contains(&candidate) {
        for byte in candidate.iter_mut().rev() {
            let (next, overflowed) = byte.overflowing_add(1);
            *byte = next;
            if !overflowed {
                break;
            }
        }
    }

    candidate
}

fn remove_duplicate_keys(updates: Vec<Update>) -> Vec<Update> {
    let mut seen = BTreeSet::new();
    updates
        .into_iter()
        .filter(|(key, _)| seen.insert(*key))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn insert_changes_root(
        key in prop::array::uniform32(any::<u8>()),
        value in values(1..64),
    ) {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        let empty_root = *tree.empty_root();

        case_result(tree.insert(key, &value))?;

        prop_assert_ne!(required_root(&tree)?, empty_root);
    }

    #[test]
    fn insert_order_is_commutative_for_distinct_keys(
        first_key in prop::array::uniform32(any::<u8>()),
        second_seed in prop::array::uniform32(any::<u8>()),
        first_value in values(1..64),
        second_value in values(1..64),
    ) {
        let second_key = absent_key(second_seed, &[(first_key, first_value.clone())]);
        let mut first_order = SparseMerkleTree::<Sha256>::new();
        let mut second_order = SparseMerkleTree::<Sha256>::new();

        case_result(first_order.insert(first_key, &first_value))?;
        case_result(first_order.insert(second_key, &second_value))?;
        case_result(second_order.insert(second_key, &second_value))?;
        case_result(second_order.insert(first_key, &first_value))?;

        prop_assert_eq!(first_order.root(), second_order.root());
    }

    #[test]
    fn membership_proof_round_trips(
        key in prop::array::uniform32(any::<u8>()),
        value in values(1..64),
    ) {
        let mut tree = SparseMerkleTree::<Sha256>::new();
        case_result(tree.insert(key, &value))?;
        let proof = case_result(tree.generate_membership_proof(key))?;
        let root = required_root(&tree)?;

        prop_assert!(SparseMerkleTree::<Sha256>::verify(&root, &value, &proof));
    }

    #[test]
    fn proof_for_never_inserted_key_verifies_non_membership(
        existing in updates(1..8),
        missing_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let existing = remove_duplicate_keys(existing);
        let missing = absent_key(missing_seed, &existing);
        let tree = build_tree(&existing)?;
        let proof = case_result(tree.generate_membership_proof(missing))?;
        let root = required_root(&tree)?;

        prop_assert!(proof.is_non_membership());
        prop_assert!(SparseMerkleTree::<Sha256>::verify_non_membership(
            &root,
            missing,
            &proof,
        ));
    }

    #[test]
    fn remove_returns_root_to_pre_insert_state(
        base in updates(0..8),
        key_seed in prop::array::uniform32(any::<u8>()),
        value in values(1..64),
    ) {
        let base = remove_duplicate_keys(base);
        let key = absent_key(key_seed, &base);
        let mut tree = build_tree(&base)?;
        let before = tree.root().copied();

        case_result(tree.insert(key, &value))?;
        case_result(tree.remove(key))?;

        prop_assert_eq!(tree.root().copied(), before);
    }

    #[test]
    fn batch_insert_matches_sequential_insert_for_any_order(
        updates in updates(1..12),
    ) {
        let mut batch_tree = SparseMerkleTree::<Sha256>::new();
        let mut sequential_tree = SparseMerkleTree::<Sha256>::new();

        case_result(batch_tree.batch_insert(&updates))?;
        for (key, value) in &updates {
            case_result(sequential_tree.insert(*key, value))?;
        }

        prop_assert_eq!(batch_tree.leaf_count(), sequential_tree.leaf_count());
        prop_assert_eq!(batch_tree.root(), sequential_tree.root());
    }

    #[test]
    fn serialized_proof_verifies_like_original(
        updates in updates(1..8),
        selected in any::<usize>(),
    ) {
        let updates = remove_duplicate_keys(updates);
        let index = selected % updates.len();
        let (key, value) = &updates[index];
        let tree = build_tree(&updates)?;
        let proof = case_result(tree.generate_membership_proof(*key))?;
        let bytes = case_result(proof.to_bytes())?;
        let recovered = case_result(SparseMerkleProof::<[u8; 32]>::from_bytes(&bytes))?;
        let root = required_root(&tree)?;

        let original_valid = SparseMerkleTree::<Sha256>::verify(&root, value, &proof);
        let recovered_valid = SparseMerkleTree::<Sha256>::verify(&root, value, &recovered);

        prop_assert_eq!(proof.siblings.len(), SPARSE_TREE_DEPTH);
        prop_assert!(original_valid);
        prop_assert_eq!(original_valid, recovered_valid);
        prop_assert_eq!(proof, recovered);
    }
}
