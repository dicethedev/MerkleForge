//! # merkle-hash :: sha256
//!
//! SHA-256 adapter for the [`HashFunction`] trait.
//!
//! SHA-256 is the most widely deployed hash function in blockchain systems.
//! It benefits from hardware acceleration (Intel SHA Extensions, ARM SHA)
//! which can yield a ~50% speed boost over software implementations on
//! supported CPUs (Drake, 2019).  This makes it a strong default for
//! production deployments that run on modern server hardware.
//!
//! ## Usage
//! ```rust,ignore
//! use merkle_hash::Sha256;
//! use merkle_core::traits::HashFunction;
//!
//! let digest = Sha256::hash(b"hello merkle");
//! assert_eq!(digest.len(), 32);
//! println!("SHA-256 name: {}", Sha256::algorithm_name());
//! ```

use merkle_core::traits::HashFunction;
use sha2::{Digest as Sha2Digest, Sha256 as Sha2_256};

/// SHA-256 implementation of [`HashFunction`].
///
/// Produces 32-byte digests.  Hardware-accelerated on x86-64 CPUs with the
/// SHA or AVX2 extension (detected at compile time by the `sha2` crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256;

impl HashFunction for Sha256 {
    /// 32-byte fixed-size digest.
    type Digest = [u8; 32];

    /// Domain-separated node hashing: `SHA-256(0x01 || left || right)`.
    ///
    /// The `0x01` prefix distinguishes internal nodes from leaf hashes
    /// (`0x00` prefix), preventing second-preimage attacks where an attacker
    /// could substitute an internal node for a leaf.
    #[inline]
    fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha2_256::new();
        hasher.update([0x01]); // internal-node domain separator
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Leaf hashing: `SHA-256(0x00 || data)`.
    ///
    /// The `0x00` prefix distinguishes leaf hashes from internal-node hashes.
    /// Callers that hash leaf data themselves should use this for correctness,
    /// but the tree implementations call it internally so most users don't
    /// need to know about it.
    #[inline]
    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha2_256::new();
        hasher.update([0x00]); // Leaf domain separator
        hasher.update(data);
        hasher.finalize().into()
    }

    #[inline]
    fn empty() -> [u8; 32] {
        // Pre-computed: SHA-256(0x00) — the canonical empty-leaf hash.
        // This avoids a runtime hash call every time we need the sentinel.
        [
            0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78,
            0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06,
            0x17, 0xaf, 0xa0, 0x1d,
        ]
    }

    fn algorithm_name() -> &'static str {
        "SHA-256"
    }

    fn digest_size() -> usize {
        32
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256(0x00) — The domain-separated empty leaf hash for MerkleForge.
    const MERKLE_EMPTY_SENTINEL: [u8; 32] = [
        0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78,
        0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06,
        0x17, 0xaf, 0xa0, 0x1d,
    ];

    #[test]
    fn digest_size_is_32() {
        assert_eq!(Sha256::digest_size(), 32);
    }

    #[test]
    fn algorithm_name() {
        assert_eq!(Sha256::algorithm_name(), "SHA-256");
    }

    #[test]
    fn hash_is_deterministic() {
        let input = b"merkleforge-test";
        assert_eq!(Sha256::hash(input), Sha256::hash(input));
    }

    #[test]
    fn empty_matches_precomputed() {
        // This ensures the library's precomputed constant matches a fresh runtime hash of the 0x00 prefix.
        let mut h = Sha2_256::new();
        h.update([0x00u8]); 
        let manual_compute: [u8; 32] = h.finalize().into();
        
        assert_eq!(Sha256::empty(), manual_compute, "Precomputed empty() must match SHA-256(0x00)");
        assert_eq!(Sha256::empty(), MERKLE_EMPTY_SENTINEL);
    }

    #[test]
    fn hash_nodes_non_commutative() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        assert_ne!(Sha256::hash_nodes(&a, &b), Sha256::hash_nodes(&b, &a));
    }

    #[test]
    fn leaf_and_node_domain_separation() {
        let data = [0xAAu8; 32];
        let dummy = [0x00u8; 32];
        
        // hash(data) uses 0x00 prefix; hash_nodes(data, dummy) uses 0x01 prefix.
        // Even if the input starts similarly, the prefixes ensure the digests differ.
        let leaf_h = Sha256::hash(&data);
        let node_h = Sha256::hash_nodes(&data, &dummy);
        
        assert_ne!(leaf_h, node_h, "Leaf and Internal Node hashes must be domain-separated");
    }

    #[test]
    fn different_inputs_different_hashes() {
        assert_ne!(Sha256::hash(b"leaf1"), Sha256::hash(b"leaf2"));
    }
}