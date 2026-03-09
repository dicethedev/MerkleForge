//! # merkle-hash :: keccak256
//!
//! Keccak-256 adapter for the [`HashFunction`] trait.
//!
//! Keccak-256 is the hash function used throughout the Ethereum Virtual
//! Machine.  It is *not* identical to the NIST SHA-3 standard (they differ
//! in the padding), which is why we use the `tiny-keccak` crate rather than
//! a generic SHA-3 crate.  This adapter is the correct choice for any tree
//! variant that needs to produce state roots compatible with Ethereum tooling
//! — most importantly the Merkle Patricia Trie.
//!
//! ## Usage
//! ```rust,ignore
//! use merkle_hash::Keccak256;
//! use merkle_core::traits::HashFunction;
//!
//! let digest = Keccak256::hash(b"hello merkle");
//! assert_eq!(digest.len(), 32);
//! ```

use merkle_core::traits::HashFunction;
use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 implementation of [`HashFunction`].
///
/// Produces 32-byte digests identical to those computed by
/// `web3.utils.keccak256` and Solidity's `keccak256()` built-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keccak256;

impl Keccak256 {
    /// Internal helper that returns a new `Keccak` hasher ready for output.
    #[inline]
    fn new_hasher() -> Keccak {
        Keccak::v256()
    }
}

impl HashFunction for Keccak256 {
    type Digest = [u8; 32];

    /// Leaf hashing: `Keccak-256(0x00 || data)`.
    #[inline]
    fn hash(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut h = Self::new_hasher();
        h.update(&[0x00]); // leaf domain separator
        h.update(data);
        h.finalize(&mut out);
        out
    }

    /// Internal node hashing: `Keccak-256(0x01 || left || right)`.
    #[inline]
    fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut h = Self::new_hasher();
        h.update(&[0x01]); // internal-node domain separator
        h.update(left);
        h.update(right);
        h.finalize(&mut out);
        out
    }

    fn algorithm_name() -> &'static str {
        "Keccak-256"
    }

    fn digest_size() -> usize {
        32
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_core::traits::HashFunction;

    /// Keccak-256("") =
    /// c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    #[test]
    fn known_vector_empty_string() {
        // Raw Keccak-256("") — no domain prefix.
        let mut out = [0u8; 32];
        let mut h = Keccak::v256();
        h.update(b"");
        h.finalize(&mut out);
        let expected = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn digest_size_is_32() {
        assert_eq!(Keccak256::digest_size(), 32);
    }

    #[test]
    fn algorithm_name() {
        assert_eq!(Keccak256::algorithm_name(), "Keccak-256");
    }

    #[test]
    fn hash_deterministic() {
        assert_eq!(Keccak256::hash(b"test"), Keccak256::hash(b"test"));
    }

    #[test]
    fn hash_nodes_non_commutative() {
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        assert_ne!(Keccak256::hash_nodes(&a, &b), Keccak256::hash_nodes(&b, &a));
    }

    #[test]
    fn hash_and_hash_nodes_differ() {
        // A leaf hash and an internal-node hash of the same bytes must differ.
        let data = [0x42u8; 32];
        let leaf = Keccak256::hash(&data);
        let node = Keccak256::hash_nodes(&data, &data);
        assert_ne!(leaf, node);
    }
}