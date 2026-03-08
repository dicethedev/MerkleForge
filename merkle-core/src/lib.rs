//! # merkle-core
//!
//! Shared traits, types, and error handling for the **MerkleForge** workspace.
//!
//! This crate is the foundation that every other crate in the workspace
//! depends on.  It contains no concrete tree logic — that lives in
//! `merkle-variants`.  Keeping the core abstract allows `merkle-bench` and
//! future crates to import only this lightweight foundation.
//!
//! ## Contents
//! | Module | Description |
//! |--------|-------------|
//! | [`error`] | Unified [`MerkleError`] enum |
//! | [`traits`] | [`HashFunction`], [`MerkleTree`], [`ProofVerifier`], [`Serializable`] |
//! | [`types`] | [`LeafIndex`], [`NodeIndex`], [`MerkleProof`], [`TreeMetadata`], etc. |
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use merkle_core::prelude::*;
//!
//! // Any type implementing HashFunction can drive a tree:
//! // use merkle_hash::Sha256;
//! // let mut tree = BinaryMerkleTree::<Sha256>::new();
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod traits;
pub mod types;

/// Re-exports of the most commonly used items.
pub mod prelude {
    pub use crate::error::MerkleError;
    pub use crate::traits::{HashFunction, MerkleTree, ProofVerifier, Serializable};
    pub use crate::types::{
        LeafIndex, MerkleProof, NodeIndex, ProofNode, ProofSide, TreeMetadata,
    };
}
