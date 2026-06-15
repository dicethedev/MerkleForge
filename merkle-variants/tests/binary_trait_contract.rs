use merkle_core::{
    error::MerkleError,
    traits::{HashFunction, MerkleTree},
    types::LeafIndex,
};
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::{Blake3, Keccak256, Sha256};

fn assert_trait_contract<H: HashFunction>() {
    let mut tree = BinaryMerkleTree::<H>::new();

    assert!(MerkleTree::<H>::is_empty(&tree));
    assert_eq!(
        MerkleTree::<H>::remove(&mut tree, LeafIndex(0)),
        Err(MerkleError::EmptyTree)
    );

    let first = MerkleTree::<H>::insert(&mut tree, b"alice").unwrap();
    let second = MerkleTree::<H>::insert(&mut tree, b"bob").unwrap();
    assert_eq!(first, LeafIndex(0));
    assert_eq!(second, LeafIndex(1));
    assert_eq!(MerkleTree::<H>::leaf_count(&tree), 2);
    assert_eq!(MerkleTree::<H>::height(&tree), 2);

    let proof = MerkleTree::<H>::generate_proof(&tree, first).unwrap();
    assert!(BinaryMerkleTree::<H>::verify(
        MerkleTree::<H>::root(&tree).unwrap(),
        b"alice",
        &proof,
    ));

    let metadata = MerkleTree::<H>::metadata(&tree);
    assert_eq!(metadata.leaf_count, 2);
    assert_eq!(metadata.height, 2);
    assert_eq!(metadata.node_count, 3);
    assert_eq!(metadata.hash_algorithm, H::algorithm_name());
    assert_eq!(metadata.variant, "BinaryMerkleTree");
}

#[test]
fn sha256_satisfies_merkle_tree_contract() {
    assert_trait_contract::<Sha256>();
}

#[test]
fn keccak256_satisfies_merkle_tree_contract() {
    assert_trait_contract::<Keccak256>();
}

#[test]
fn blake3_satisfies_merkle_tree_contract() {
    assert_trait_contract::<Blake3>();
}
