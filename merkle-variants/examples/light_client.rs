use merkle_core::{error::MerkleError, types::LeafIndex};
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;

fn main() -> Result<(), MerkleError> {
    let proof;
    let root;

    {
        let mut tree = BinaryMerkleTree::<Sha256>::new();
        tree.insert(b"tx:alice->bob:100")?;
        tree.insert(b"tx:bob->carol:50")?;
        tree.insert(b"tx:carol->dave:25")?;

        root = *tree.root().expect("tree has inserted leaves");
        proof = tree.generate_proof(LeafIndex(0))?;

        println!("server: built tree and exported root + proof");
    }

    let valid = BinaryMerkleTree::<Sha256>::verify(&root, b"tx:alice->bob:100", &proof);

    println!("client: tree dropped before verification");
    println!("Stateless verification: {valid}");

    Ok(())
}
