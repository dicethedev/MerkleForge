# merkle-core

> Shared traits, types, and error handling for the `MerkleForge` workspace.

[![Crates.io](https://img.shields.io/crates/v/merkle-core.svg)](https://crates.io/crates/merkle-core)
[![docs.rs](https://docs.rs/merkle-core/badge.svg)](https://docs.rs/merkle-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

---

`merkle-core` is the foundation crate of `MerkleForge`. It defines the **traits, types, and errors** that every other crate in the workspace depends on — with no concrete tree logic of its own. This separation means you can take a dependency on `merkle-core` alone if you want to write your own tree variant or hash adapter without pulling in any implementation code.
 
---

## Contents

| Module | What's inside |
|--------|---------------|
| [`traits::HashFunction`](#hashfunction) | Pluggable crypto abstraction — swap SHA-256 for BLAKE3 at the call site |
| [`traits::MerkleTree`](#merkletree) | Universal interface every tree variant implements |
| [`traits::ProofVerifier`](#proofverifier) | Stateless inclusion-proof verification (no tree required) |
| [`traits::Serializable`](#serializable) | Blanket `serde` + `bincode` impl for proofs and tree state |
| [`types`](#types) | `LeafIndex`, `NodeIndex`, `MerkleProof`, `ProofNode`, `ProofSide`, `TreeMetadata` |
| [`error::MerkleError`](#merkleerror) | Unified, `#[non_exhaustive]` error enum |

---

## Installation

```toml
[dependencies]
merkle-core = "0.1"
```

For the ready-made hash adapters (SHA-256, Keccak-256, BLAKE3):

```toml
[dependencies]
merkle-core = "0.1"
merkle-hash = "0.1"
```

---

## Traits

### `HashFunction`

The pluggable cryptographic abstraction at the heart of the library. Every tree type is generic over `H: HashFunction`, so swapping algorithms requires changing one type parameter — zero changes to tree logic, zero runtime overhead (Rust monomorphises the generic away at compile time).

```rust
use merkle_core::traits::HashFunction;

pub struct Sha256;

impl HashFunction for Sha256 {
    type Digest = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        // leaf domain separation: H(0x00 || data)
        sha2::Sha256::digest([&[0x00], data].concat()).into()
    }

    fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        // internal-node domain separation: H(0x01 || left || right)
        sha2::Sha256::digest([&[0x01], left.as_ref(), right.as_ref()].concat()).into()
    }

    fn algorithm_name() -> &'static str { "SHA-256" }
    fn digest_size() -> usize { 32 }
}
```

**Required methods:**

| Method | Description |
|--------|-------------|
| `hash(data: &[u8]) -> Self::Digest` | Hash a leaf pre-image |
| `algorithm_name() -> &'static str` | Human-readable name, e.g. `"SHA-256"` |
| `digest_size() -> usize` | Output size in bytes |

**Provided methods (override if needed):**

| Method | Default behaviour |
|--------|------------------|
| `hash_nodes(left, right) -> Self::Digest` | Concatenates `left \|\| right` then calls `hash` |
| `empty() -> Self::Digest` | Returns `hash(&[])` — the canonical empty-slot sentinel |

**Digest bounds.** The associated type `Digest` must satisfy:

```
AsRef<[u8]> + Clone + Debug + PartialEq + Eq + Send + Sync + 'static
```

`[u8; 32]` satisfies all of these, making it the natural choice for 256-bit hash functions.

**Domain separation.** The adapters in `merkle-hash` use prefix bytes to distinguish leaf hashes (`0x00 || data`) from internal-node hashes (`0x01 || left || right`). This prevents second-preimage attacks where an attacker submits an internal node in place of a leaf. If you implement `HashFunction` yourself, follow the same convention.

---

### `MerkleTree`

The universal interface that `BinaryMerkleTree`, `SparseMerkleTree`, and `MerklePatriciaTrie` all implement. Using this trait as a bound means your code works with every variant without modification.

```rust
pub trait MerkleTree<H: HashFunction>: Sized {
    fn insert(&mut self, data: &[u8]) -> Result<LeafIndex, MerkleError>;
    fn remove(&mut self, index: LeafIndex) -> Result<(), MerkleError>;

    fn root(&self) -> Option<&H::Digest>;
    fn leaf_count(&self) -> usize;
    fn is_empty(&self) -> bool;       // provided — delegates to leaf_count
    fn height(&self) -> usize;

    fn generate_proof(&self, index: LeafIndex) -> Result<MerkleProof<H::Digest>, MerkleError>;
    fn metadata(&self) -> TreeMetadata;
}
```

Writing generic code over any tree variant:

```rust
use merkle_core::prelude::*;

fn print_root<H, T>(tree: &T)
where
    H: HashFunction,
    T: MerkleTree<H>,
{
    match tree.root() {
        Some(root) => println!("root: {:?}", root),
        None       => println!("tree is empty"),
    }
}
```

---

### `ProofVerifier`

Stateless inclusion-proof verification. An implementor needs **only the root hash and the proof** — it does not hold or reference the tree. This maps directly to the "light client" model: a mobile wallet can verify a transaction exists in a block using just the block header root and a small `O(log n)` proof, without downloading the full block.

```rust
pub trait ProofVerifier<H: HashFunction> {
    fn verify(
        expected_root: &H::Digest,
        leaf_data:     &[u8],
        proof:         &MerkleProof<H::Digest>,
    ) -> bool;
}
```

The verification algorithm:

```
1. current ← H(0x00 || leaf_data)
2. for each ProofNode { hash: sibling, side } in proof.path:
     if side == Left:  current ← H(0x01 || sibling || current)
     if side == Right: current ← H(0x01 || current || sibling)
3. return current == expected_root
```

Concrete implementations live in `merkle-variants`. The trait is kept separate so it can be implemented on a **zero-sized struct** with no tree allocation — useful in constrained environments.

---

### `Serializable`

A blanket implementation over any `serde::Serialize + DeserializeOwned` type using `bincode` for compact binary encoding. This means `MerkleProof<D>` and `TreeMetadata` are automatically serialisable with no extra derives.

```rust
use merkle_core::prelude::*;

// MerkleProof<[u8; 32]> gets Serializable for free via the blanket impl
let proof: MerkleProof<[u8; 32]> = /* ... */;

// Persist to bytes (e.g. write to a database or send over a socket)
let bytes = proof.to_bytes()?;

// Reconstruct on the other side
let recovered = MerkleProof::<[u8; 32]>::from_bytes(&bytes)?;

assert_eq!(proof, recovered);
```

**Methods:**

| Method | Description |
|--------|-------------|
| `to_bytes(&self) -> Result<Vec<u8>, MerkleError>` | Serialise to `bincode` bytes |
| `from_bytes(bytes: &[u8]) -> Result<Self, MerkleError>` | Deserialise from `bincode` bytes |
| `serialized_size(&self) -> Result<usize, MerkleError>` | Byte length without retaining the buffer |

---

## Types

### `LeafIndex` and `NodeIndex`

Strongly-typed index wrappers that prevent accidentally passing an internal-node index where a leaf index is expected. A `LeafIndex` can be converted to a `NodeIndex`, but not the other way around.

```rust
use merkle_core::types::{LeafIndex, NodeIndex};

let leaf = LeafIndex(2);
let node: NodeIndex = leaf.into();   // fine
// let leaf2: LeafIndex = node.into();  // compile error — no such impl

// Root index for a tree with 4 leaves: 2*4 - 1 = 7
assert_eq!(NodeIndex::root(4), NodeIndex(7));
```

---

### `MerkleProof<D>`

An inclusion proof for a single leaf carrying `O(log n)` sibling hashes.

```rust
pub struct MerkleProof<D> {
    pub leaf_index: LeafIndex,   // which leaf this proof is for
    pub leaf_count: usize,       // tree size at proof-generation time
    pub path:       Vec<ProofNode<D>>,  // siblings, bottom-up
}
```

Useful methods:

```rust
let depth = proof.depth();        // == proof.path.len()
let trivial = proof.is_trivial(); // true for a single-leaf tree
```

---

### `ProofNode<D>` and `ProofSide`

Each step along the proof path:

```rust
pub struct ProofNode<D> {
    pub hash: D,          // the sibling's digest at this level
    pub side: ProofSide,  // which side the sibling sits on
}

pub enum ProofSide {
    Left,   // sibling is left child; current hash is right
    Right,  // sibling is right child; current hash is left
}
```

`ProofSide` determines concatenation order during verification. Getting it wrong would produce a different root, making the proof fail — which is exactly the desired behaviour for a tampered proof.

---

### `TreeMetadata`

A lightweight snapshot of a tree's current state, returned by `MerkleTree::metadata()`. Useful for logging and benchmarking without exposing internal structure.

```rust
pub struct TreeMetadata {
    pub leaf_count:     usize,
    pub height:         usize,
    pub node_count:     usize,
    pub hash_algorithm: &'static str,   // e.g. "SHA-256"
    pub variant:        &'static str,   // e.g. "BinaryMerkleTree"
}
```

---

## `MerkleError`

Every fallible function in the workspace returns `Result<T, MerkleError>`. The enum is `#[non_exhaustive]` so new variants can be added in minor releases without breaking downstream `match` expressions.

```rust
use merkle_core::error::MerkleError;

match result {
    Err(MerkleError::EmptyTree) => { /* no leaves inserted yet */ }
    Err(MerkleError::IndexOutOfBounds { index, len }) => {
        eprintln!("asked for leaf {index} but tree only has {len}");
    }
    Err(MerkleError::InvalidProof) => { /* proof tampered or stale */ }
    Err(MerkleError::EmptyLeafData) => { /* caller passed b"" */ }
    Err(MerkleError::SerializationError(msg)) => { eprintln!("{msg}") }
    Err(MerkleError::DeserializationError(msg)) => { eprintln!("{msg}") }
    Err(MerkleError::RlpError(msg)) => { /* Patricia Trie codec issue */ }
    Err(_) => { /* forward-compatible catch-all */ }
    Ok(value) => { /* ... */ }
}
```

All variants implement `std::error::Error + Display`. `bincode::Error` converts into `MerkleError::SerializationError` via `From`.

**All variants:**

| Variant | When it occurs |
|---------|----------------|
| `EmptyTree` | Operation needs ≥1 leaf but the tree is empty |
| `IndexOutOfBounds { index, len }` | Requested index ≥ current leaf count |
| `InvalidProof` | Reconstructed root doesn't match expected root |
| `InvalidProofStructure(String)` | Proof path length inconsistent with stated index/leaf count |
| `EmptyLeafData` | Caller passed a zero-length byte slice to `insert` |
| `SerializationError(String)` | `bincode` or other codec failed to encode |
| `DeserializationError(String)` | Byte slice is malformed or wrong format |
| `HashError(String)` | Internal hashing step failed unexpectedly |
| `UnsupportedOperation(&'static str)` | Operation not available for this tree variant |
| `RlpError(String)` | RLP encode/decode error (Patricia Trie only) |

---

## The `prelude`

Import the most commonly used items in one line:

```rust
use merkle_core::prelude::*;

// Now in scope:
// MerkleError
// HashFunction, MerkleTree, ProofVerifier, Serializable
// LeafIndex, NodeIndex, MerkleProof, ProofNode, ProofSide, TreeMetadata
```

---

## Implementing a custom `HashFunction`

If the three adapters in `merkle-hash` don't cover your use case, implement the trait directly. The only hard requirements are:

1. `Digest` satisfies the required bounds.
2. `hash` and `hash_nodes` are deterministic and collision-resistant.
3. You use distinct domain prefixes for leaf vs. internal-node hashing.

```rust
use merkle_core::traits::HashFunction;

/// Example: a test-only XOR hash — never use in production.
pub struct Xor8;

impl HashFunction for Xor8 {
    type Digest = [u8; 1];

    fn hash(data: &[u8]) -> [u8; 1] {
        [data.iter().fold(0u8, |acc, &b| acc ^ b)]
    }

    // hash_nodes and empty have sensible defaults — override if needed

    fn algorithm_name() -> &'static str { "XOR8" }
    fn digest_size() -> usize { 1 }
}
```

---

## Safety

`#[forbid(unsafe_code)]` is set at the crate root. `merkle-core` contains no unsafe blocks and never will.

---

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) at your option.