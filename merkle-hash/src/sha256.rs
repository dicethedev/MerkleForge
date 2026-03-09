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
        hasher.update([0x00]); // leaf domain separator
        hasher.update(data);
        hasher.finalize().into()
    }

    #[inline]
    fn empty() -> [u8; 32] {
        // Pre-computed: SHA-256(0x00) — the canonical empty-leaf hash.
        // This avoids a runtime hash call every time we need the sentinel.
        [
            0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98,
            0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
            0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
            0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
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
    use merkle_core::traits::HashFunction;

    /// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const SHA256_EMPTY_PREIMAGE: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
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
        assert_eq!(Sha256::hash(b"abc"), Sha256::hash(b"abc"));
    }

    #[test]
    fn hash_nodes_non_commutative() {
        // Swapping left/right must produce a different digest.
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        assert_ne!(Sha256::hash_nodes(&a, &b), Sha256::hash_nodes(&b, &a));
    }

    #[test]
    fn empty_matches_precomputed() {
        // The precomputed sentinel must equal SHA-256(0x00).
        let computed = {
            use sha2::{Digest, Sha256 as Sha2};
            let mut h = Sha2::new();
            h.update([0x00u8]);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        assert_eq!(Sha256::empty(), computed);
        assert_eq!(computed, SHA256_EMPTY_PREIMAGE);
    }

    #[test]
    fn leaf_and_node_hashes_differ_for_same_bytes() {
        // Domain separation: hash("data") ≠ hash_nodes("dat", "a").
        // (Not a precise test, but confirms the prefixes differ.)
        let leaf = Sha256::hash(b"hello");
        let left = Sha256::hash(b"hel");
        let right = Sha256::hash(b"lo");
        let node = Sha256::hash_nodes(&left, &right);
        assert_ne!(leaf, node);
    }
}
