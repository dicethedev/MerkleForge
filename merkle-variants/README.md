# merkle-variants

> Merkle tree implementations for the MerkleForge Rust workspace.

[![Crates.io](https://img.shields.io/crates/v/merkle-variants.svg)](https://crates.io/crates/merkle-variants)
[![docs.rs](https://docs.rs/merkle-variants/badge.svg)](https://docs.rs/merkle-variants)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`merkle-variants` provides Merkle tree implementations built on the generic
traits from [`merkle-core`](https://crates.io/crates/merkle-core). Tree logic
is generic over `H: HashFunction`, allowing applications to select a hash
algorithm without changing the tree API.

## Status

| Variant | Status | Intended use |
| --- | --- | --- |
| `BinaryMerkleTree<H>` | Available | Transaction batches, inclusion proofs, and append-oriented datasets |
| `SparseMerkleTree<H>` | Planned | Large sparse key spaces and authenticated state |
| `MerklePatriciaTrie<H>` | Planned | Ethereum-compatible state tries |

This is research software and has not been independently security-audited.

## Installation

```toml
[dependencies]
merkle-core = "0.2"
merkle-variants = "0.2"
merkleforge-hash = "0.2"
```

`merkleforge-hash` supplies the SHA-256, Keccak-256, and BLAKE3 adapters. You
can omit it when providing your own `HashFunction` implementation.

## Example

```rust
use merkle_core::{
    traits::MerkleTree,
    types::LeafIndex,
};
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;

fn main() -> Result<(), merkle_core::error::MerkleError> {
    let mut tree = BinaryMerkleTree::<Sha256>::new();
    tree.insert(b"alice:100")?;
    tree.insert(b"bob:250")?;

    let proof = tree.generate_proof(LeafIndex(0))?;
    let root = tree.root().expect("the tree is not empty");

    assert!(BinaryMerkleTree::<Sha256>::verify(
        root,
        b"alice:100",
        &proof,
    ));

    let metadata = tree.metadata();
    assert_eq!(metadata.variant, "BinaryMerkleTree");
    assert_eq!(metadata.hash_algorithm, "SHA-256");

    Ok(())
}
```

## Binary Tree Features

- Flat, cache-friendly node storage
- Automatic power-of-two padding
- Stable leaf indices for interior removals
- Generic `MerkleTree<H>` implementation
- Stateless inclusion-proof verification
- Metadata describing the tree and selected hash algorithm
- Property-based tests and Criterion benchmarks
- `#[forbid(unsafe_code)]`

## Documentation

- [API documentation](https://docs.rs/merkle-variants)
- [MerkleForge repository](https://github.com/dicethedev/MerkleForge)
- [Performance dashboard](https://dicethedev.github.io/MerkleForge/index.html)

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
