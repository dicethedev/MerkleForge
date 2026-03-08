//! # merkle-core :: traits :: hash_function
//!
//! The `HashFunction` trait is the **pluggable crypto abstraction** at the
//! heart of the library.  By parameterising every tree type over
//! `H: HashFunction`, callers can swap SHA-256 for BLAKE3 with zero changes
//! to tree logic and zero runtime cost (Rust monomorphises the generics).
//!
//! ## Implementing `HashFunction`
//!
//! ```rust,ignore
//! use merkle_core::traits::HashFunction;
//!
//! pub struct MyHash;
//!
//! impl HashFunction for MyHash {
//!     type Digest = [u8; 32];
//!
//!     fn hash(data: &[u8]) -> Self::Digest { /* ... */ }
//!
//!     fn hash_nodes(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
//!         let mut combined = Vec::with_capacity(64);
//!         combined.extend_from_slice(left);
//!         combined.extend_from_slice(right);
//!         Self::hash(&combined)
//!     }
//!
//!     fn algorithm_name() -> &'static str { "MyHash" }
//! }
//! ```

use std::fmt::Debug;

/// Abstraction over a cryptographic hash function used by Merkle trees.
///
/// # Type parameter `Digest`
/// The associated type `Digest` represents a fixed-size hash output.  It
/// must be:
/// - `Clone` — nodes are cloned when building the tree.
/// - `PartialEq + Eq` — so roots and proof hashes can be compared.
/// - `AsRef<[u8]>` — for serialisation and concatenation before hashing.
/// - `Debug` — for test output and diagnostic messages.
/// - `Send + Sync` — so trees can be used across thread boundaries.
///
/// # Zero-cost abstractions
/// All methods are `#[inline]` by convention in implementors.  Rust's
/// monomorphisation ensures that no vtable dispatch overhead occurs when
/// calling through `H: HashFunction` bounds.
pub trait HashFunction: Send + Sync + 'static {
    /// The concrete digest type produced by this hash function.
    type Digest: AsRef<[u8]>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static;

    // ── Core hashing ──────────────────────────────────────────────────────

    /// Hash arbitrary bytes and return the digest.
    fn hash(data: &[u8]) -> Self::Digest;

    /// Hash two child digests together to produce a parent digest.
    ///
    /// The default implementation concatenates `left || right` and calls
    /// `Self::hash`.  Override this to use domain separation or a different
    /// concatenation strategy.
    fn hash_nodes(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        let mut combined = Vec::with_capacity(
            left.as_ref().len() + right.as_ref().len(),
        );
        combined.extend_from_slice(left.as_ref());
        combined.extend_from_slice(right.as_ref());
        Self::hash(&combined)
    }

    /// Return the canonical "empty" digest used to pad trees to a
    /// power-of-two size, or to represent vacant slots in sparse trees.
    ///
    /// The default is the hash of a zero-length byte slice.
    fn empty() -> Self::Digest {
        Self::hash(&[])
    }

    // ── Metadata ──────────────────────────────────────────────────────────

    /// Human-readable name of the algorithm, e.g. `"SHA-256"` or `"BLAKE3"`.
    fn algorithm_name() -> &'static str;

    /// Output size of the digest in bytes.
    fn digest_size() -> usize;
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// A minimal stub `HashFunction` used only in unit tests so that
    /// `merkle-core` has no dependency on `merkle-hash` at test time.
    use super::*;

    struct Xor8;

    impl HashFunction for Xor8 {
        type Digest = [u8; 1];

        fn hash(data: &[u8]) -> [u8; 1] {
            [data.iter().fold(0u8, |acc, &b| acc ^ b)]
        }

        fn algorithm_name() -> &'static str {
            "XOR8"
        }

        fn digest_size() -> usize {
            1
        }
    }

    #[test]
    fn hash_deterministic() {
        let a = Xor8::hash(b"hello");
        let b = Xor8::hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_nodes_uses_concatenation() {
        let l = Xor8::hash(b"left");
        let r = Xor8::hash(b"right");
        let parent = Xor8::hash_nodes(&l, &r);
        // Manually: xor(l, r) because XOR8(a || b) = XOR(a, b) for single bytes
        let expected = [l[0] ^ r[0]];
        assert_eq!(parent, expected);
    }

    #[test]
    fn empty_is_hash_of_empty_slice() {
        assert_eq!(Xor8::empty(), Xor8::hash(&[]));
    }

    #[test]
    fn metadata() {
        assert_eq!(Xor8::algorithm_name(), "XOR8");
        assert_eq!(Xor8::digest_size(), 1);
    }
}
