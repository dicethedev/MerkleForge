# merkleforge-hash

> Official hash adapters for MerkleForge Framework: SHA-256, Keccak-256, and
> BLAKE3.

[![Crates.io](https://img.shields.io/crates/v/merkleforge-hash.svg)](https://crates.io/crates/merkleforge-hash)
[![docs.rs](https://docs.rs/merkleforge-hash/badge.svg)](https://docs.rs/merkleforge-hash)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`merkleforge-hash` provides ready-made implementations of
`merkle_core::traits::HashFunction`. These adapters can drive every tree in
`merkle-variants`, so applications can switch hash algorithms by changing a
single generic type.

## Installation

```toml
[dependencies]
merkle-core = "0.4.1"
merkleforge-hash = "0.4.1"
```

Add `merkle-variants` when you want complete tree implementations:

```toml
[dependencies]
merkle-core = "0.4.1"
merkleforge-hash = "0.4.1"
merkle-variants = "0.4.1"
```

## Quick Start

```rust
use merkle_core::traits::HashFunction;
use merkleforge_hash::{Blake3, Keccak256, Sha256};

let sha = Sha256::hash(b"alice:100");
let keccak = Keccak256::hash(b"alice:100");
let blake = Blake3::hash(b"alice:100");

assert_eq!(sha.len(), 32);
assert_eq!(keccak.len(), 32);
assert_eq!(blake.len(), 32);
assert_ne!(sha, keccak);
assert_ne!(sha, blake);
```

Use an adapter with a tree:

```rust
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;

let mut tree = BinaryMerkleTree::<Sha256>::new();
```

## Available Adapters

| Adapter | Algorithm | Digest | Best for |
| --- | --- | --- | --- |
| `Sha256` | SHA-256 | 32 bytes | Interoperable binary and sparse trees |
| `Keccak256` | Keccak-256 | 32 bytes | Ethereum-compatible Patricia trie roots |
| `Blake3` | BLAKE3 | 32 bytes | High-throughput non-Ethereum workloads |

## Domain Separation

Merkle trees must avoid confusing leaf data with internal node data. The
official adapters separate those domains:

| Adapter | Leaf domain | Internal-node domain |
| --- | --- | --- |
| `Sha256` | `SHA-256(0x00 || data)` | `SHA-256(0x01 || left || right)` |
| `Keccak256` | `Keccak-256(0x00 || data)` | `Keccak-256(0x01 || left || right)` |
| `Blake3` | `derive_key("MerkleForge 2026 leaf v1", data)` | `derive_key("MerkleForge 2026 internal-node v1", left || right)` |

Custom `HashFunction` implementations should preserve the same invariant.

## Choosing an Adapter

- Use `Keccak256` when roots must match Ethereum tooling.
- Use `Sha256` when broad interoperability or hardware SHA support matters.
- Use `Blake3` when raw software throughput matters and Ethereum compatibility
  is not required.

Benchmark data is available in [`BENCHMARKS.md`](../BENCHMARKS.md) and on the
public benchmark dashboard.

## Links

- API docs: <https://docs.rs/merkleforge-hash>
- Repository: <https://github.com/dicethedev/MerkleForge>
- Website: <https://dicethedev.github.io/MerkleForge/>

## Safety

`merkleforge-hash` uses `#![forbid(unsafe_code)]`. The crate contains no unsafe
blocks.

Security note: MerkleForge Framework has not yet completed an independent
security audit. Review the code and threat model before using it in
security-critical environments.

## License

Licensed under either of:

- [MIT License](../LICENSE)
- [Apache License, Version 2.0](../LICENSE-APACHE)

at your option.
