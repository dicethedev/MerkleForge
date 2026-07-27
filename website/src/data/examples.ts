export const binaryExample = `use merkle_core::{traits::MerkleTree, types::LeafIndex};
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;

fn main() -> Result<(), merkle_core::error::MerkleError> {
    let mut tree = BinaryMerkleTree::<Sha256>::new();
    tree.insert(b"alice:100")?;
    tree.insert(b"bob:250")?;

    let proof = tree.generate_proof(LeafIndex(0))?;
    let root = tree.root().expect("tree is not empty");

    assert!(BinaryMerkleTree::<Sha256>::verify(
        root,
        b"alice:100",
        &proof,
    ));
    Ok(())
}`;

export const exampleBuild = `use merkle_core::{traits::MerkleTree, types::LeafIndex};
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;

let mut tree = BinaryMerkleTree::<Sha256>::new();
tree.insert(b"alice")?;
tree.insert(b"bob")?;

let proof = tree.generate_proof(LeafIndex(0))?;
let root = tree.root().unwrap();
assert!(BinaryMerkleTree::<Sha256>::verify(
    root, b"alice", &proof
));`;

export const exampleHashing = `use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::{Blake3, Keccak256, Sha256};

let sha_tree = BinaryMerkleTree::<Sha256>::new();
let eth_tree = BinaryMerkleTree::<Keccak256>::new();
let fast_tree = BinaryMerkleTree::<Blake3>::new();`;

export const exampleDirectHash = `use merkle_core::traits::HashFunction;
use merkleforge_hash::Blake3;

let left = Blake3::hash(b"left leaf");
let right = Blake3::hash(b"right leaf");
let parent = Blake3::hash_nodes(&left, &right);

assert_eq!(Blake3::digest_size(), 32);
assert_eq!(Blake3::algorithm_name(), "BLAKE3");`;

export const exampleMetadata = `use merkle_core::traits::MerkleTree;

let metadata = tree.metadata();
println!("variant: {}", metadata.variant);
println!("algorithm: {}", metadata.hash_algorithm);
println!("leaves: {}", metadata.leaf_count);
println!("height: {}", metadata.height);
println!("allocated nodes: {}", metadata.node_count);`;

export const exampleSerialization = `use merkle_core::{
    traits::Serializable,
    types::MerkleProof,
};

let bytes = proof.to_bytes()?;
let recovered =
    MerkleProof::<[u8; 32]>::from_bytes(&bytes)?;

assert_eq!(proof, recovered);`;

export const sparseExample = `use merkle_variants::SparseMerkleTree;
use merkleforge_hash::Sha256;

fn main() -> Result<(), merkle_core::error::MerkleError> {
    let mut state = SparseMerkleTree::<Sha256>::new();
    let alice = [7_u8; 32];
    let bob = [9_u8; 32];

    state.insert(alice, b"balance:100")?;
    state.insert(bob, b"balance:250")?;

    let proof = state.generate_membership_proof(alice)?;
    let root = state.root_hash();

    assert!(SparseMerkleTree::<Sha256>::verify(
        &root,
        b"balance:100",
        &proof,
    ));
    Ok(())
}`;

export const patriciaExample = `use merkle_variants::MerklePatriciaTrie;
use merkleforge_hash::Keccak256;

fn main() -> Result<(), merkle_core::error::MerkleError> {
    let mut trie = MerklePatriciaTrie::<Keccak256>::new();

    trie.insert(b"account:alice", b"100")?;
    trie.insert(b"account:bob", b"250")?;

    let proof = trie.generate_proof(b"account:alice")?;
    let root = trie.root_hash();

    assert!(MerklePatriciaTrie::<Keccak256>::verify(
        &root,
        b"account:alice",
        b"100",
        &proof,
    ));
    Ok(())
}`;
