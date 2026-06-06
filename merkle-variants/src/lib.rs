//! Merkle tree implementations for the `MerkleForge` workspace.
//!
//! This crate will provide binary, sparse, and Patricia Merkle trees built on
//! the shared abstractions from `merkle-core` and hash adapters from
//! `merkleforge-hash`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod binary;
pub mod patricia;
pub mod sparse;
