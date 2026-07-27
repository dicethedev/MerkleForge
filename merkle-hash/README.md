# merkleforge-hash

> Pluggable cryptographic hash adapters for `MerkleForge` — SHA-256, Keccak-256, and BLAKE3.

[![Crates.io](https://img.shields.io/crates/v/merkleforge-hash.svg)](https://crates.io/crates/merkleforge-hash)
[![docs.rs](https://docs.rs/merkleforge-hash/badge.svg)](https://docs.rs/merkleforge-hash)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

---

> **Research Software — Not Production Ready**
>
> MerkleForge is a final-year academic research project. This crate has not
> been independently security-audited. Use at your own risk.

---

`merkleforge-hash` provides the hash adapters used by `MerkleForge`. Each
adapter implements the
[`HashFunction`](https://docs.rs/merkle-core/latest/merkle_core/traits/hash_function/trait.HashFunction.html)
trait from `merkle-core`, so every tree in `merkle-variants` can switch hash
algorithms through a single type parameter.

## Installation

```toml
[dependencies]
merkle-core = "0.4"
merkleforge-hash = "0.4"
```

All three adapters are compiled by default.

Add `merkle-variants = "0.4"` when you want to use these adapters with the
published tree implementations.

## Quick Start

```rust
use merkle_core::traits::HashFunction;
use merkleforge_hash::{Blake3, Keccak256, Sha256};

let sha_digest = Sha256::hash(b"alice:100");
let keccak_digest = Keccak256::hash(b"alice:100");
let blake_digest = Blake3::hash(b"alice:100");

assert_eq!(sha_digest.len(), 32);
assert_eq!(keccak_digest.len(), 32);
assert_eq!(blake_digest.len(), 32);
assert_ne!(sha_digest, keccak_digest);
assert_ne!(sha_digest, blake_digest);
```

Using an adapter with a tree:

```rust
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;

let mut tree = BinaryMerkleTree::<Sha256>::new();
```

## Adapters

| Adapter | Algorithm | Output | Best for |
| --- | --- | --- | --- |
| `Sha256` | SHA-256 | 32 bytes | Widely interoperable binary and sparse trees |
| `Keccak256` | Keccak-256 | 32 bytes | Ethereum-compatible `MerklePatriciaTrie` roots |
| `Blake3` | BLAKE3 | 32 bytes | High-throughput non-Ethereum workloads |

## Domain Separation

The adapters separate leaf hashing from internal-node hashing:

| Adapter | Leaf domain | Internal-node domain |
| --- | --- | --- |
| `Sha256` | `SHA-256(0x00 || data)` | `SHA-256(0x01 || left || right)` |
| `Keccak256` | `Keccak-256(0x00 || data)` | `Keccak-256(0x01 || left || right)` |
| `Blake3` | `derive_key("MerkleForge 2026 leaf v1", data)` | `derive_key("MerkleForge 2026 internal-node v1", left || right)` |

This prevents a proof from confusing a leaf pre-image with an encoded internal
node. Custom `HashFunction` implementations should preserve the same invariant.

## Choosing An Adapter

- Use `Keccak256` when a `MerklePatriciaTrie` root must match Ethereum tooling.
- Use `Sha256` when interoperability and hardware SHA support matter.
- Use `Blake3` when raw software throughput matters and Ethereum compatibility
  is not required.

## Safety

`#[forbid(unsafe_code)]` is set at the crate root. `merkleforge-hash` contains
no unsafe blocks.

## License

Licensed under either of:

- [MIT License](../LICENSE)
- [Apache License, Version 2.0](../LICENSE-APACHE)

at your option.
