//! # merkle-hash
//!
//! Pluggable cryptographic hash adapters for **`MerkleForge`**.
//!
//! Each adapter wraps a well-tested upstream crate and implements the
//! [`HashFunction`] trait so it can drive any tree variant in `merkle-variants`.
//!
//! ## Available adapters
//!
//! | Type | Algorithm | Digest | Best for |
//! |------|-----------|--------|----------|
//! | [`Sha256`] | SHA-256 | 32 bytes | Hardware-accelerated production deployments |
//! | [`Keccak256`] | Keccak-256 | 32 bytes | Ethereum-compatible Patricia Tries |
//! | [`Blake3`] | BLAKE3 | 32 bytes | Maximum throughput on modern CPUs |
//!
//! ## Choosing a hash function
//!
//! - **SHA-256**: Excellent choice when targeting x86-64 hardware with SHA
//!   extensions. Widely used in Bitcoin and many Ethereum-adjacent systems.
//! - **Keccak-256**: Required for any tree that must produce state roots
//!   readable by Ethereum tooling (e.g. the `MerklePatriciaTrie` variant).
//! - **BLAKE3**: Fastest on software paths, good for throughput-sensitive
//!   workloads where Ethereum compatibility is not required.
//!
//! Concrete benchmark numbers will be published in the Phase 5 report.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod blake3;
mod keccak256;
mod sha256;

pub use crate::blake3::Blake3;
pub use crate::keccak256::Keccak256;
pub use crate::sha256::Sha256;

/// Re-export of the [`HashFunction`] trait for convenience.
pub use merkle_core::traits::HashFunction;