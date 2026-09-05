# merkle-core

> Shared traits, proof types, metadata, serialization helpers, and error types
> for the MerkleForge Framework workspace.

[![Crates.io](https://img.shields.io/crates/v/merkle-core.svg)](https://crates.io/crates/merkle-core)
[![docs.rs](https://docs.rs/merkle-core/badge.svg)](https://docs.rs/merkle-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`merkle-core` is the small foundation crate behind MerkleForge Framework. It
contains no concrete tree implementation. Instead, it defines the contracts
that hash adapters and tree variants use to interoperate.

Use this crate when you want to:

- depend only on the shared Merkle interfaces;
- implement a custom Merkle tree variant;
- implement a custom hash adapter;
- exchange Merkle proofs and metadata without pulling in concrete trees;
- compile shared proof types in `no_std` + `alloc` environments.

## Installation

```toml
[dependencies]
merkle-core = "0.4.1"
```

For bare-metal or embedded targets with `alloc`:

```toml
[dependencies]
merkle-core = { version = "0.4.1", default-features = false, features = ["alloc"] }
```

The default `std` feature is recommended for normal server, CLI, and desktop
applications.

## Feature Flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `std` | Yes | Enables standard-library integration, including `std::error::Error` |
| `alloc` | Via `std` | Enables heap-backed types such as `Vec` and `String` for `no_std` builds |

Check a bare-metal target:

```bash
rustup target add thumbv7em-none-eabihf
cargo check -p merkle-core \
  --no-default-features \
  --features alloc \
  --target thumbv7em-none-eabihf
```

## API Surface

| Module | What it provides |
| --- | --- |
| `traits::HashFunction` | Pluggable hash adapter contract |
| `traits::MerkleTree` | Common tree interface for insert, remove, root, proof, and metadata |
| `traits::ProofVerifier` | Stateless proof verification contract |
| `traits::Serializable` | Blanket `serde` + `bincode` serialization helpers |
| `types` | `LeafIndex`, `NodeIndex`, `MerkleProof`, `ProofNode`, `ProofSide`, `TreeMetadata` |
| `error::MerkleError` | Unified non-exhaustive error enum |
| `prelude` | Convenient import set for application code |

## Quick Start

Most application code imports the prelude and uses a concrete tree from
`merkle-variants`:

```rust
use merkle_core::prelude::*;
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;

fn main() -> Result<(), MerkleError> {
    let mut tree = BinaryMerkleTree::<Sha256>::new();

    tree.insert(b"alice:100")?;
    tree.insert(b"bob:250")?;

    let proof = tree.generate_proof(LeafIndex(0))?;
    let root = tree.root().expect("tree is not empty");

    assert!(BinaryMerkleTree::<Sha256>::verify(
        root,
        b"alice:100",
        &proof,
    ));

    Ok(())
}
```

## Core Traits

### `HashFunction`

`HashFunction` lets every tree stay generic over the hashing algorithm.
Changing from SHA-256 to BLAKE3 is a type-level choice, not a runtime branch.

```rust
pub trait HashFunction {
    type Digest;

    fn hash(data: &[u8]) -> Self::Digest;
    fn algorithm_name() -> &'static str;
    fn digest_size() -> usize;

    fn hash_nodes(left: &Self::Digest, right: &Self::Digest) -> Self::Digest;
    fn empty() -> Self::Digest;
}
```

Implementations should domain-separate leaf hashing from internal-node hashing.
The adapters in `merkleforge-hash` use separate leaf and node domains so proofs
cannot confuse raw leaf data with encoded internal nodes.

### `MerkleTree`

`MerkleTree` is the common interface implemented by Binary, Sparse, and
Patricia variants:

```rust
pub trait MerkleTree<H: HashFunction> {
    fn insert(&mut self, data: &[u8]) -> Result<LeafIndex, MerkleError>;
    fn remove(&mut self, index: LeafIndex) -> Result<(), MerkleError>;
    fn root(&self) -> Option<&H::Digest>;
    fn leaf_count(&self) -> usize;
    fn height(&self) -> usize;
    fn generate_proof(&self, index: LeafIndex) -> Result<MerkleProof<H::Digest>, MerkleError>;
    fn metadata(&self) -> TreeMetadata;
}
```

Specialized trees may also expose native APIs. For example,
`SparseMerkleTree` supports 256-bit key-addressed operations and
`MerklePatriciaTrie` supports byte-key/value operations for Ethereum-style
state.

### `ProofVerifier`

`ProofVerifier` supports light-client style verification. A verifier needs only
the trusted root, the target value, and the proof.

```rust
pub trait ProofVerifier<H: HashFunction> {
    fn verify(
        expected_root: &H::Digest,
        leaf_data: &[u8],
        proof: &MerkleProof<H::Digest>,
    ) -> bool;
}
```

### `Serializable`

`Serializable` provides compact binary encoding through `bincode`:

```rust
use merkle_core::prelude::*;

let bytes = proof.to_bytes()?;
let recovered = MerkleProof::<[u8; 32]>::from_bytes(&bytes)?;
assert_eq!(proof, recovered);
```

## Core Types

| Type | Purpose |
| --- | --- |
| `LeafIndex` | Strongly typed leaf-layer index |
| `NodeIndex` | Strongly typed flat-array node index |
| `ProofSide` | Indicates whether a proof sibling is left or right |
| `ProofNode<D>` | One sibling hash in a proof path |
| `MerkleProof<D>` | Inclusion proof for one leaf |
| `TreeMetadata` | Variant, hash algorithm, height, leaf count, and node count |

## Error Handling

Every fallible API uses `Result<T, MerkleError>`.

```rust
use merkle_core::error::MerkleError;

match result {
    Err(MerkleError::EmptyTree) => eprintln!("tree has no leaves"),
    Err(MerkleError::IndexOutOfBounds { index, len }) => {
        eprintln!("leaf {index} is outside the current leaf count {len}");
    }
    Err(MerkleError::InvalidProof) => eprintln!("proof is stale or tampered"),
    Err(MerkleError::EmptyLeafData) => eprintln!("empty leaves are rejected"),
    Err(other) => eprintln!("{other}"),
    Ok(value) => {
        // use value
    }
}
```

`MerkleError` is `#[non_exhaustive]`, so downstream code should keep a fallback
match arm for forward compatibility.

## Workspace Links

- Tree implementations: [`merkle-variants`](https://crates.io/crates/merkle-variants)
- Hash adapters: [`merkleforge-hash`](https://crates.io/crates/merkleforge-hash)
- API docs: <https://docs.rs/merkle-core>
- Repository: <https://github.com/dicethedev/MerkleForge>
- Website: <https://dicethedev.github.io/MerkleForge/>

## Safety

`merkle-core` uses `#![forbid(unsafe_code)]`. The crate contains no unsafe
blocks.

Security note: MerkleForge Framework has not yet completed an independent
security audit. Review the code and threat model before using it in
security-critical environments.

## License

Licensed under either of:

- [MIT License](../LICENSE)
- [Apache License, Version 2.0](../LICENSE-APACHE)

at your option.
