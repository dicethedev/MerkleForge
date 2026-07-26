use std::{collections::BTreeSet, fmt::Display};

use merkle_core::traits::Serializable;
use merkle_variants::{
    MerklePatriciaTrie, MptProof,
    patricia::{MptNode, NibblePath, NodeRef, rlp_decode, rlp_encode},
};
use merkleforge_hash::Keccak256;
use proptest::{collection::vec, prelude::*, test_runner::TestCaseError};

type Key = Vec<u8>;
type Value = Vec<u8>;
type Update = (Key, Value);

fn keys(range: std::ops::Range<usize>) -> impl Strategy<Value = Key> {
    vec(any::<u8>(), range)
}

fn values(range: std::ops::Range<usize>) -> impl Strategy<Value = Value> {
    vec(any::<u8>(), range)
}

fn updates(range: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Update>> {
    vec((keys(0..24), values(1..64)), range)
}

fn unique_updates(range: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Update>> {
    updates(range).prop_filter("at least five unique keys", |updates| {
        updates
            .iter()
            .map(|(key, _)| key)
            .collect::<BTreeSet<_>>()
            .len()
            >= 5
    })
}

fn nibble_paths() -> impl Strategy<Value = NibblePath> {
    (keys(0..16), any::<usize>()).prop_map(|(key, start)| {
        let path = NibblePath::from_key(&key);
        path.slice(start % (path.len() + 1))
    })
}

fn generated_nodes() -> impl Strategy<Value = MptNode<[u8; 32]>> {
    prop_oneof![
        Just(MptNode::Empty),
        (nibble_paths(), values(0..64))
            .prop_map(|(key_suffix, value)| { MptNode::Leaf { key_suffix, value } }),
        (nibble_paths(), nibble_paths(), values(0..64)).prop_map(
            |(shared_prefix, key_suffix, value)| {
                let child = MptNode::<[u8; 32]>::Leaf { key_suffix, value };
                MptNode::Extension {
                    shared_prefix,
                    child: NodeRef::Inline(rlp_encode(&child)),
                }
            }
        ),
        (
            0_u8..16,
            nibble_paths(),
            values(0..64),
            prop::option::of(values(1..64))
        )
            .prop_map(|(slot, key_suffix, child_value, branch_value)| {
                let mut children = Box::new(std::array::from_fn(|_| NodeRef::Inline(vec![0x80])));
                let child = MptNode::<[u8; 32]>::Leaf {
                    key_suffix,
                    value: child_value,
                };
                children[usize::from(slot)] = NodeRef::Inline(rlp_encode(&child));

                MptNode::Branch {
                    children,
                    value: branch_value,
                }
            }),
    ]
}

fn case_result<T, E: Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn required_root(tree: &MerklePatriciaTrie<Keccak256>) -> Result<[u8; 32], TestCaseError> {
    tree.root()
        .copied()
        .ok_or_else(|| TestCaseError::fail("non-empty Patricia trie did not have a root"))
}

fn build_tree(updates: &[Update]) -> Result<MerklePatriciaTrie<Keccak256>, TestCaseError> {
    let mut tree = MerklePatriciaTrie::new();
    for (key, value) in updates {
        case_result(tree.insert(key, value))?;
    }
    Ok(tree)
}

fn absent_key(seed: Key, present: &[Key]) -> Key {
    let present = present.iter().collect::<BTreeSet<_>>();
    let mut candidate = seed;

    while present.contains(&candidate) {
        candidate.push(0);
    }

    candidate
}

fn unique_by_key(updates: Vec<Update>) -> Vec<Update> {
    let mut seen = BTreeSet::new();
    updates
        .into_iter()
        .filter(|(key, _)| seen.insert(key.clone()))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn insert_then_get_returns_inserted_value(
        key in keys(0..32),
        value in values(1..64),
    ) {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        case_result(tree.insert(&key, &value))?;

        prop_assert_eq!(tree.get(&key), Some(value.as_slice()));
    }

    #[test]
    fn remove_then_get_returns_none(
        key in keys(0..32),
        value in values(1..64),
    ) {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        case_result(tree.insert(&key, &value))?;
        case_result(tree.remove(&key))?;

        prop_assert_eq!(tree.get(&key), None);
        prop_assert!(tree.is_empty());
    }

    #[test]
    fn insert_changes_root(
        key in keys(0..32),
        value in values(1..64),
    ) {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();
        let before = tree.root().copied();

        case_result(tree.insert(&key, &value))?;

        prop_assert_ne!(tree.root().copied(), before);
    }

    #[test]
    fn remove_changes_root(
        updates in updates(1..12),
        selected in any::<usize>(),
    ) {
        let updates = unique_by_key(updates);
        let index = selected % updates.len();
        let mut tree = build_tree(&updates)?;
        let before = tree.root().copied();

        case_result(tree.remove(&updates[index].0))?;

        prop_assert_ne!(tree.root().copied(), before);
    }

    #[test]
    fn inserting_one_key_preserves_another_key(
        first_key in keys(0..24),
        second_seed in keys(0..24),
        first_value in values(1..64),
        second_value in values(1..64),
    ) {
        let second_key = absent_key(second_seed, std::slice::from_ref(&first_key));
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        case_result(tree.insert(&first_key, &first_value))?;
        case_result(tree.insert(&second_key, &second_value))?;

        prop_assert_eq!(tree.get(&first_key), Some(first_value.as_slice()));
        prop_assert_eq!(tree.get(&second_key), Some(second_value.as_slice()));
    }

    #[test]
    fn insert_order_is_canonical_for_same_key_set(
        updates in unique_updates(5..16),
    ) {
        let updates = unique_by_key(updates);
        prop_assume!(updates.len() >= 5);
        let mut first_order = MerklePatriciaTrie::<Keccak256>::new();
        let mut reverse_order = MerklePatriciaTrie::<Keccak256>::new();

        for (key, value) in &updates {
            case_result(first_order.insert(key, value))?;
        }
        for (key, value) in updates.iter().rev() {
            case_result(reverse_order.insert(key, value))?;
        }

        prop_assert_eq!(required_root(&first_order)?, required_root(&reverse_order)?);
    }

    #[test]
    fn proof_generated_after_insert_verifies(
        key in keys(0..32),
        value in values(1..64),
    ) {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        case_result(tree.insert(&key, &value))?;
        let proof = case_result(tree.generate_proof(&key))?;
        let root = required_root(&tree)?;

        prop_assert!(proof.is_membership());
        prop_assert!(MerklePatriciaTrie::<Keccak256>::verify_proof(&root, &proof));
    }

    #[test]
    fn rlp_round_trips_generated_nodes(
        node in generated_nodes(),
    ) {
        let encoded = rlp_encode(&node);
        let decoded = case_result(rlp_decode::<[u8; 32]>(&encoded))?;

        prop_assert_eq!(decoded, node);
    }

    #[test]
    fn serialized_proof_verifies_like_original(
        updates in updates(1..12),
        selected in any::<usize>(),
    ) {
        let updates = unique_by_key(updates);
        let index = selected % updates.len();
        let tree = build_tree(&updates)?;
        let (key, _) = &updates[index];
        let proof = case_result(tree.generate_proof(key))?;
        let bytes = case_result(proof.to_bytes())?;
        let recovered = case_result(MptProof::<[u8; 32]>::from_bytes(&bytes))?;
        let root = required_root(&tree)?;

        let original_valid = MerklePatriciaTrie::<Keccak256>::verify_proof(&root, &proof);
        let recovered_valid = MerklePatriciaTrie::<Keccak256>::verify_proof(&root, &recovered);

        prop_assert!(original_valid);
        prop_assert_eq!(original_valid, recovered_valid);
        prop_assert_eq!(proof, recovered);
    }
}
