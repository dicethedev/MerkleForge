# merkle-hash

> Pluggable cryptographic hash adapters for `MerkleForge` — SHA-256, Keccak-256, and BLAKE3.

[![Crates.io](https://img.shields.io/crates/v/merkle-hash.svg)](https://crates.io/crates/merkle-hash)
[![docs.rs](https://docs.rs/merkle-hash/badge.svg)](https://docs.rs/merkle-hash)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

---

`merkle-hash` provides the three hash function adapters used by `MerkleForge`. Each one implements the [`HashFunction`](https://docs.rs/merkle-core/latest/merkle_core/traits/trait.HashFunction.html) trait from `merkle-core`, so any tree variant in `merkle-variants` can be driven by any adapter — swapping algorithms is a one-type-parameter change with zero runtime overhead.

---

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Adapters](#adapters)
  - [Sha256](#sha256)
  - [Keccak256](#keccak256)
  - [Blake3](#blake3)
- [Choosing an adapter](#choosing-an-adapter)
- [Benchmark comparison](#benchmark-comparison)
- [Domain separation](#domain-separation)
- [Implementing a custom `HashFunction`](#implementing-a-custom-hashfunction)
- [Safety](#safety)
- [License](#license)

---

## Installation

```toml
[dependencies]
merkle-hash = "0.1"
merkle-core = "0.1"
```

All three adapters are compiled by default. There are no feature flags, the upstream crates (`sha2`, `tiny-keccak`, `blake3`) are small and compile quickly.

---

## Quick start

```rust
use merkle_hash::{Sha256, Keccak256, Blake3, HashFunction};

// Hash a leaf pre-image
let sha_digest   = Sha256::hash(b"alice:100");
let keccak_digest = Keccak256::hash(b"alice:100");
let blake_digest  = Blake3::hash(b"alice:100");

// All three produce 32-byte digests
assert_eq!(sha_digest.len(),    32);
assert_eq!(keccak_digest.len(), 32);
assert_eq!(blake_digest.len(),  32);

// The digests are different — three distinct algorithms
assert_ne!(sha_digest, keccak_digest);
assert_ne!(sha_digest, blake_digest);

// Hash two child nodes together to form a parent
let parent = Sha256::hash_nodes(&sha_digest, &sha_digest);
assert_eq!(parent.len(), 32);
```

Swapping the hash function that drives a tree:

```rust
// Before — SHA-256
let mut tree = BinaryMerkleTree::<Sha256>::new();

// After — BLAKE3, same API, zero other changes
let mut tree = BinaryMerkleTree::<Blake3>::new();
```

---

## Adapters

### `Sha256`

```rust
use merkle_hash::{Sha256, HashFunction};

let digest = Sha256::hash(b"transaction data");
// digest: [u8; 32]

let parent = Sha256::hash_nodes(&digest, &digest);
// parent: [u8; 32]

println!("{}", Sha256::algorithm_name()); // "SHA-256"
println!("{}", Sha256::digest_size());    // 32
```

**Upstream crate:** [`sha2`](https://crates.io/crates/sha2)

**Hardware acceleration:** The `sha2` crate detects Intel SHA Extensions and AVX2 at compile time and uses them automatically. On supported x86-64 CPUs this yields roughly a 50% throughput improvement over the software path (Drake, 2019).

**Domain separation:**
- Leaf hash: `SHA-256(0x00 || data)`
- Internal node hash: `SHA-256(0x01 || left || right)`

**`empty()` sentinel:** Pre-computed as `SHA-256(0x00)` — avoids a runtime hash call every time the tree needs an empty-slot placeholder.

```
empty = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb3378768501a30617afa01d
```

---

### `Keccak256`

```rust
use merkle_hash::{Keccak256, HashFunction};

let digest = Keccak256::hash(b"transaction data");
// digest: [u8; 32]  — identical to web3.utils.keccak256("transaction data")

println!("{}", Keccak256::algorithm_name()); // "Keccak-256"
```

**Upstream crate:** [`tiny-keccak`](https://crates.io/crates/tiny-keccak) with the `keccak` feature

> **Important:** Keccak-256 is **not** the same as NIST SHA-3. They use different padding. If you need to produce digests that match Ethereum tooling (`web3.utils.keccak256`, Solidity's `keccak256()`, `ethers.utils.keccak256`), use `Keccak256`. Using any SHA-3 crate will produce different output.

**When to use:** Any tree that must produce state roots verifiable by Ethereum tooling — most importantly the `MerklePatriciaTrie` variant.

**Domain separation:**
- Leaf hash: `Keccak-256(0x00 || data)`
- Internal node hash: `Keccak-256(0x01 || left || right)`

**Known vector:**

```
Keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
```

---

### `Blake3`

```rust
use merkle_hash::{Blake3, HashFunction};

let digest = Blake3::hash(b"transaction data");
// digest: [u8; 32]

println!("{}", Blake3::algorithm_name()); // "BLAKE3"
```

**Upstream crate:** [`blake3`](https://crates.io/crates/blake3)

**Domain separation:** BLAKE3 has native support for context strings via `blake3::derive_key`. This is cryptographically cleaner and more efficient than prepending a prefix byte — no extra memory allocation, no length extension risk.

```rust
// Internally, Blake3 uses:
const LEAF_CONTEXT: &str = "MerkleForge 2026 leaf v1";
const NODE_CONTEXT: &str = "MerkleForge 2024 internal-node v1";

// Leaf:  blake3::derive_key("MerkleForge 2026 leaf v1",          data)
// Node:  blake3::derive_key("MerkleForge 2026 internal-node v1", left || right)
```

Because the context strings are distinct and fixed, leaf and internal-node digests are guaranteed to never collide regardless of input.

**When to use:** Throughput-sensitive workloads where Ethereum compatibility is not required — background indexers, proof batch generation, high-frequency state updates.

---

## Choosing an adapter

| | `Sha256` | `Keccak256` | `Blake3` |
|---|---|---|---|
| **Algorithm** | SHA-256 | Keccak-256 | BLAKE3 |
| **Digest size** | 32 bytes | 32 bytes | 32 bytes |
| **Ethereum compatible** | ✗ | ✅ Required for MPT | ✗ |
| **Hardware acceleration** | ✅ SHA/AVX2 extensions | ✗ software only | ✅ SIMD, multi-core |
| **Software throughput** | Moderate | Moderate | Fastest |
| **Domain separation method** | `0x00`/`0x01` prefix bytes | `0x00`/`0x01` prefix bytes | `derive_key` context strings |
| **Best for** | Production x86-64, Bitcoin-style SPV | Any Ethereum-compatible tree | Maximum throughput, non-Ethereum |

**Decision guide:**

- Building a `MerklePatriciaTrie` whose roots need to match Ethereum → **`Keccak256`**, no choice.
- Running on a modern server with SHA Extensions or on ARM with SHA instructions → **`Sha256`** will match or beat BLAKE3 on hardware paths.
- Building a binary or sparse tree where raw throughput matters and Ethereum compatibility is not required → **`Blake3`**.
- Not sure? Start with **`Sha256`** — it's the most battle-tested, has the widest hardware support, and will be easy to reason about in security reviews.

---

## Benchmark comparison

> **Note:** The numbers below are from published literature (AITCS, 2024; Drake, 2019). The `merkle-bench` crate will produce project-specific numbers on standardised hardware in Phase 5 of the implementation roadmap. Those results will replace this table.

### Single-block throughput (software path, ~64 bytes)

| Algorithm | Approx. latency | Notes |
|-----------|----------------|-------|
| BLAKE3 | ~100–120 ns | Fastest on software path across all input sizes |
| SHA-256 (software) | ~250–300 ns | 50% slower than BLAKE3 without hardware extensions |
| SHA-256 (hardware) | ~120–150 ns | SHA Extensions close the gap significantly |
| Keccak-256 | ~300–400 ns | No hardware acceleration; consistently slowest |

### Sustained throughput (large buffers, MB/s)

| Algorithm | Typical throughput | Scales across cores? |
|-----------|-------------------|----------------------|
| BLAKE3 | 1–4 GB/s | ✅ Internal tree parallelism |
| SHA-256 (hardware) | 500 MB/s–1 GB/s | ✗ Single-core |
| SHA-256 (software) | 200–400 MB/s | ✗ Single-core |
| Keccak-256 | 150–300 MB/s | ✗ Single-core |

These gaps directly determine tree construction speed. A tree with 1,000,000 leaves requires roughly 2,000,000 hash calls (one per leaf plus one per internal node). At 64 bytes per input:

| Algorithm | Estimated construction time (1M leaves) |
|-----------|----------------------------------------|
| BLAKE3 | ~200–400 ms |
| SHA-256 (hardware) | ~300–600 ms |
| SHA-256 (software) | ~500 ms–1 s |
| Keccak-256 | ~600 ms–1.2 s |

The `merkle-bench` Criterion suite (`cargo bench --bench hash_throughput`) measures your specific hardware so you can make an informed decision rather than relying on generalised figures.

---

## Domain separation

All three adapters enforce domain separation between leaf hashes and internal-node hashes. This prevents a class of second-preimage attacks where an attacker constructs a proof by substituting an internal node for a leaf.

**The attack without domain separation:**

```
Suppose H(A || B) == H(leaf_data).
An attacker could present [A, B] as a "leaf" and fool a verifier
that checks only the final root, not whether the proof path is valid.
```

**How each adapter prevents it:**

| Adapter | Leaf | Internal node |
|---------|------|---------------|
| `Sha256` | `SHA-256(0x00 \|d\| data)` | `SHA-256(0x01 \|\| left \|\| right)` |
| `Keccak256` | `Keccak-256(0x00 \|\| data)` | `Keccak-256(0x01 \|\| left \|\| right)` |
| `Blake3` | `derive_key("MerkleForge 2026 leaf v1", data)` | `derive_key("MerkleForge 2026 internal-node v1", left \|\| right)` |
d
The `0x00`/`0x01` byte prefix used by `Sha256` and `Keccak256` follows RFC 6962 (Certificate Transparency). BLAKE3's `derive_key` mode is equivalent but uses full context strings instead of a single byte, which is both more readable and more collision-resistant at the domain boundary.

If you implement a custom `HashFunction`, you **must** apply the same separation. The `ProofVerifier` in `merkle-core` assumes it.

---

## Implementing a custom `HashFunction`

If none of the three adapters fit your use case — say, you need BLAKE2b for a specific protocol, or a truncated digest for a constrained environment — implement the trait directly in your own crate.

### Minimal implementation

```rust
use merkle_core::traits::HashFunction;

pub struct MyHash;

impl HashFunction for MyHash {
    type Digest = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        // REQUIRED: leaf domain separation
        // Prefix 0x00 before hashing so leaf digests can never
        // collide with internal-node digests.
        todo!("your_hash_crate::hash([0x00, data].concat())")
    }

    fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        // REQUIRED: internal-node domain separation
        // Prefix 0x01 so this can never equal a leaf hash.
        todo!("your_hash_crate::hash([0x01, left, right].concat())")
    }

    fn algorithm_name() -> &'static str { "MyHash-256" }
    fn digest_size() -> usize { 32 }
}
```

### Full example — BLAKE2b-256

```rust
use merkle_core::traits::HashFunction;
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

pub struct Blake2b256;

impl HashFunction for Blake2b256 {
    type Digest = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Blake2b::<U32>::new();
        h.update([0x00]); // leaf prefix
        h.update(data);
        h.finalize().into()
    }

    fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Blake2b::<U32>::new();
        h.update([0x01]); // internal-node prefix
        h.update(left);
        h.update(right);
        h.finalize().into()
    }

    fn algorithm_name() -> &'static str { "BLAKE2b-256" }
    fn digest_size() -> usize { 32 }
}
```

Once implemented, `Blake2b256` drops straight into any `merkle-variants` tree:

```rust
let mut tree = BinaryMerkleTree::<Blake2b256>::new();
tree.insert(b"leaf data")?;
```

### Checklist before shipping a custom adapter

- [ ] `hash` applies a distinct domain prefix or context to leaf inputs
- [ ] `hash_nodes` applies a different domain prefix or context to node inputs
- [ ] `hash_nodes` is **non-commutative** — `H(A, B) ≠ H(B, A)` for most inputs
- [ ] `Digest` implements `AsRef<[u8]> + Clone + Debug + PartialEq + Eq + Send + Sync + 'static`
- [ ] The implementation is deterministic — same input always produces the same output
- [ ] `digest_size()` returns the correct byte length of `Digest`
- [ ] If you override `empty()`, it equals `hash(&[])` or an equally valid sentinel

### Using a non-32-byte digest

The `Digest` associated type is not constrained to `[u8; 32]`. You can use any fixed-size array, or a custom newtype, as long as it satisfies the bounds:

```rust
pub struct Truncated128;

impl HashFunction for Truncated128 {
    type Digest = [u8; 16];   // 128-bit output

    fn hash(data: &[u8]) -> [u8; 16] {
        let full = Sha256::hash(data); // compute full SHA-256
        full[..16].try_into().unwrap() // truncate to 128 bits
    }

    fn hash_nodes(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
        let mut buf = [0u8; 33]; // 0x01 + 16 + 16
        buf[0] = 0x01;
        buf[1..17].copy_from_slice(left);
        buf[17..33].copy_from_slice(right);
        let full = Sha256::hash(&buf);
        full[..16].try_into().unwrap()
    }

    fn algorithm_name() -> &'static str { "SHA-256/128" }
    fn digest_size() -> usize { 16 }
}
```

> **Warning:** Truncating a digest reduces collision resistance. A 128-bit digest has a birthday-bound collision probability of ~2⁻⁶⁴. Use a full-width digest for any production security context.

---

## Safety

`#[forbid(unsafe_code)]` is set at the crate root. `merkle-hash` contains no unsafe blocks. All three upstream crates (`sha2`, `tiny-keccak`, `blake3`) are widely audited and used in production blockchain infrastructure.

---

## License

Licensed under either of [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) at your option.