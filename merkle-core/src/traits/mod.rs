//! All core traits for the MerkleForge workspace.
pub mod hash_function;
pub mod merkle_tree;
pub mod serializable;

pub use hash_function::HashFunction;
pub use merkle_tree::{MerkleTree, ProofVerifier};
pub use serializable::Serializable;
