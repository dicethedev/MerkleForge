# MerkleForge

> A high-performance, unified Merkle tree library for the Rust ecosystem.

[![CI](https://github.com/dicethedev/MerkleForge/actions/workflows/ci.yml/badge.svg)](https://github.com/dicethedev/MerkleForge/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/merkle-core.svg)](https://crates.io/crates/merkle-core)
[![docs.rs](https://docs.rs/merkle-core/badge.svg)](https://docs.rs/merkle-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

---
 
> ⚠️ **Research Software — Not Production Ready**
>
> MerkleForge is a final-year academic research project exploring the design,
> implementation, and benchmarking of Merkle tree variants in Rust. The codebase
> has not been independently security-audited. While correctness is a core goal
> and the library is covered by unit, property-based, and integration tests,
> no guarantees are made about its fitness for use in production systems,
> financial applications, or any environment where cryptographic correctness
> is safety-critical.
>
> Use at your own risk. Feedback and bug reports are welcome.

---

## The Problem
 
One of the major bottlenecks in modern blockchain networks is data verification. As blockchain systems process millions of transactions, verifying the integrity of state data becomes increasingly slow and resource-intensive. Every state lookup, transaction batch, and light-client proof depends on the speed, efficiency, and correctness of the underlying data structure.
 
The Rust ecosystem makes this worse by being fragmented. Libraries like `rs-merkle` cover only binary trees, while Ethereum-specific crates are maintained separately and incompatibly. Developers are forced to wire together niche tools that differ in documentation quality, testing coverage, and performance with no way to compare them systematically.

## The Solution
 
MerkleForge is a high-performance Rust toolkit designed to attack this bottleneck directly. It provides an optimized, energy-efficient engine capable
of generating fast cryptographic proofs, enabling distributed systems to validate data integrity without overwhelming storage or computational resources.
 
The toolkit unifies the three Merkle tree variants used across production blockchain systems — binary trees for transaction batching, sparse trees for
account state, and Patricia tries for Ethereum compatibility — under a single cohesive API with pluggable hash functions and a rigorous benchmarking suite.
 
This is the implementation artifact of a final-year Software Engineering research project at MIVA Open University, supervised by Dr. Oluwasegun Ishaya Adelaiye.
 
---
 
## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Workspace Structure](#workspace-structure)
- [Getting Started](#getting-started)
- [Hash Functions](#hash-functions)
- [Tree Variants](#tree-variants)
- [Proof Generation & Verification](#proof-generation--verification)
- [Benchmarking](#benchmarking)
- [Development Status](#development-status)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

---

## Features

- **Unified API** — `BinaryMerkleTree<H>`, `SparseMerkleTree<H>`, and
  `MerklePatriciaTrie<H>` all implement the same `MerkleTree<H>` trait.
  Switch variants without rewriting your integration code.
- **Pluggable hash functions** — swap SHA-256, Keccak-256, and BLAKE3 with
  zero changes to tree logic. Rust generics monomorphise at compile time —
  no runtime overhead.
- **Zero-cost abstractions** — the `MerkleTree<H: HashFunction>` bound
  compiles to the same machine code as a hand-rolled implementation for
  each hash.
- **Stateless proof verification** — the `ProofVerifier` module lets light
  clients verify inclusion proofs using only the root hash, without storing
  the full tree.
- **Energy-efficient design** — BLAKE3's lower CPU cycles per byte directly
  reduces energy consumption per proof. The benchmarking suite measures
  this across all three algorithms so you can make hardware-specific choices.
- **Systematic benchmarking** — a dedicated `merkle-bench` crate runs
  Criterion statistical benchmarks (mean/median/stddev) across all tree
  sizes and hash algorithms.
- **Property-based testing** — Proptest verifies mathematical invariants:
  any leaf change must update the root; a corrupted proof must fail
  verification.
- **`#[forbid(unsafe_code)]`** — guaranteed memory safety across the entire
  workspace.
- **CI/CD** — GitHub Actions runs tests, Clippy (pedantic), `rustfmt`,
  doc builds, and a benchmark compile check on every push.

---

## Architecture

The toolkit is structured in two logical layers:

```
┌──────────────────────────────────────────────────────────────────────┐
│                          merkle-core                                 │
│  HashFunction trait · MerkleTree trait · ProofVerifier trait         │
│  MerkleProof · LeafIndex · NodeIndex · MerkleError                   │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ depends on
          ┌──────────────────┼───────────────────┐
          ▼                  ▼                   ▼
  merkleforge-hash    merkle-variants        merkle-bench
  SHA-256 adapter    BinaryMerkleTree     Criterion suite
  Keccak-256         SparseMerkleTree     baseline_construction
  BLAKE3             PatriciaTrie         hash_throughput
```
 

### Trait Hierarchy

```
HashFunction  ←  pluggable crypto abstraction
      │
      └──▶  MerkleTree<H: HashFunction>
                 insert() · remove() · root()
                 generate_proof() · metadata()
                      │
                      └──▶  ProofVerifier<H>  (stateless)
                                verify(root, leaf_data, proof)
```

Domain separation is enforced at the hash level:
- Leaf hashes: `H(0x00 || data)`
- Internal node hashes: `H(0x01 || left || right)`

This prevents second-preimage attacks where an attacker substitutes an
internal node for a leaf.
 
---

## Workspace Structure

```
MerkleForge/
├── Cargo.toml                        # workspace manifest + shared dep versions
│
├── merkle-core/                      # foundation — traits, types, errors
│   └── src/
│       ├── lib.rs
│       ├── error.rs                  # MerkleError (non_exhaustive)
│       ├── traits/
│       │   ├── hash_function.rs      # HashFunction trait
│       │   ├── merkle_tree.rs        # MerkleTree + ProofVerifier traits
│       │   └── serializable.rs       # blanket serde/bincode impl
│       └── types/
│           └── common.rs             # NodeIndex, LeafIndex, MerkleProof, ...
│
├── merkle-hash/                      # pluggable hash adapters
│   └── src/
│       ├── lib.rs
│       ├── sha256.rs
│       ├── keccak256.rs
│       └── blake3.rs
│
├── merkle-variants/                  # concrete tree implementations
│   └── src/
│       ├── lib.rs
│       ├── binary.rs                 # Phase 2
│       ├── sparse.rs                 # Phase 3
│       └── patricia.rs               # Phase 4
│
├── merkle-bench/                     # isolated benchmarking crate
│   ├── benches/
│   │   ├── baseline_construction.rs  # leaf + node hashing latency
│   │   └── hash_throughput.rs        # sustained MB/s per algorithm
│   └── src/lib.rs
│
└── .github/workflows/ci.yml          # automated test · lint · bench · docs
```
> **Note on crate names:** The folder names above reflect the workspace
> directory structure. The published crate names on crates.io are
> `merkle-core` and `merkleforge-hash` (the original names were
> already taken).
 
---

## Getting Started
 
Add the crates you need to your `Cargo.toml`:
 
```toml
[dependencies]
merkle-core = "0.1"
merkleforge-hash = "0.1"
merkle-variants = "0.1"   # implementations arrive across Phase 2–4
```

### Quick example (once `BinaryMerkleTree` lands in Phase 2)
 
```rust
use merkleforge_hash::Sha256;
use merkle_variants::BinaryMerkleTree;
use merkle_core::prelude::*;
 
fn main() -> Result<(), MerkleError> {
    let mut tree = BinaryMerkleTree::<Sha256>::new();
 
    tree.insert(b"alice:100")?;
    tree.insert(b"bob:250")?;
    tree.insert(b"carol:75")?;
 
    let root = tree.root().expect("tree is non-empty");
    println!("Root: {:?}", root);
 
    // Generate an inclusion proof for leaf 0 (alice)
    let proof = tree.generate_proof(LeafIndex(0))?;
    println!("Proof depth: {}", proof.depth());
 
    // Stateless verification — no tree needed
    let valid = BinaryMerkleTree::<Sha256>::verify(root, b"alice:100", &proof);
    assert!(valid);
    Ok(())
}
```

### Swap the hash function
 
```rust
// From SHA-256 to BLAKE3 — one type parameter, zero other changes
use merkleforge_hash::Blake3;
let mut tree = BinaryMerkleTree::<Blake3>::new();
```

### Building and testing

Cargo is the workspace build system, with `make` providing convenient
wrappers for common development tasks:

```bash
# Format all Rust code
make fmt

# Run Clippy across the workspace with warnings denied
make lint

# Run all workspace tests in release mode
make test
```

---

## Hash Functions
 
| Type | Algorithm | Output | Best for |
|------|-----------|--------|----------|
| `Sha256` | SHA-256 | 32 bytes | Production deployments with hardware SHA extensions |
| `Keccak256` | Keccak-256 | 32 bytes | Ethereum-compatible Patricia Tries |
| `Blake3` | BLAKE3 | 32 bytes | Maximum throughput and lowest energy cost per proof |
 
All three adapters implement `HashFunction` with domain-separated leaf and
internal-node hashing. SHA-256 and Keccak-256 use `0x00`/`0x01` byte
prefixes; BLAKE3 uses its native `derive_key` mode with context strings for
zero-overhead domain separation.
 
Full benchmark data comparing throughput, latency, and energy efficiency
across all three will be published after Phase 5.
 
---

## Tree Variants
 
| Crate | Variant | Status | Best for |
|-------|---------|--------|----------|
| `merkle-variants` | `BinaryMerkleTree<H>` | 🔨 Phase 2 | Transaction batching, Bitcoin-style SPV |
| `merkle-variants` | `SparseMerkleTree<H>` | ⏳ Phase 3 | Account state, Layer-2 rollups |
| `merkle-variants` | `MerklePatriciaTrie<H>` | ⏳ Phase 4 | Ethereum state roots, EVM compatibility |

### Binary Merkle Tree
Balanced, power-of-two tree with iterative bottom-up construction. Optimised
for throughput when the full leaf set is known at build time. Proof size is
`O(log n)`

### Sparse Merkle Tree
256-bit key space (2²⁵⁶ possible slots). Implements shortcut nodes
(Buterin, 2018), precomputed empty-hash caching, and node batching
(Ouvrard, 2018/2019) for sub-linear memory and storage use on mostly-empty
trees. Supports one-phase batch updates (Ma et al., 2023) for rollup
workloads — directly reducing the storage overhead that makes Layer-2
verification expensive.
 
### Merkle Patricia Trie
Ethereum-compatible trie with four node types (branch, extension, leaf,
empty), RLP encoding, and state-root outputs that match Ethereum mainnet.
Validated against official Ethereum test vectors.

---

## Proof Generation & Verification
 
A `MerkleProof<D>` carries the sibling hashes along the path from a specific
leaf to the root:
 
```rust
pub struct MerkleProof<D> {
    pub leaf_index: LeafIndex,
    pub leaf_count: usize,
    pub path:       Vec<ProofNode<D>>,   // O(log n) siblings
}
```

**Verification is stateless** — a light client needs only the root hash
(e.g. from a trusted block header) and the proof. No full tree. No full
block. This is the core property that makes MerkleForge useful for
resource-constrained nodes:
 
```
1. current = H(0x00 || leaf_data)
2. for each ProofNode in proof.path:
     if side == Left:  current = H(0x01 || sibling || current)
     if side == Right: current = H(0x01 || current || sibling)
3. return current == expected_root
```

Proofs are `serde`-serialisable out of the box via the blanket `Serializable`
impl — store them in a database or send them over a network with no extra
setup.
 
---
 
## Benchmarking
 
The `merkle-bench` crate provides an isolated Criterion suite that reports
mean, median, and standard deviation to eliminate noise.
 
```bash
# Run all benchmarks and open the HTML report
cargo bench --workspace
open target/criterion/report/index.html
 
# Run just the hash throughput comparison
cargo bench --bench hash_throughput
```
 
| Metric | Status |
|--------|--------|
| Construction latency — leaf hash + node combine | ✅ Phase 1 |
| Throughput — sustained MB/s per algorithm (32 B → 1 MB) | ✅ Phase 1 |
| Tree construction — 100 / 1K / 10K / 100K / 1M leaves | 🔜 Phase 5 |
| Proof generation & verification latency | 🔜 Phase 5 |
| Proof size in bytes | 🔜 Phase 5 |
| Peak memory consumption (RSS) | 🔜 Phase 5 |
| Comparative results vs `rs-merkle` and `merkle_light` | 🔜 Phase 5 |
 
---

## Development Status
 
| Phase | Scope | Status |
|-------|-------|--------|
| 1 — Core Infrastructure | Trait hierarchy, hash adapters, CI/CD | ✅ **Complete** |
| 2 — Binary Merkle Tree | `BinaryMerkleTree<H>`, property tests | 🔨 **In Progress** |
| 3 — Sparse Merkle Tree | `SparseMerkleTree<H>`, node batching | ⏳ Planned |
| 4 — Merkle Patricia Trie | Ethereum-compatible MPT, RLP | ⏳ Planned |
| 5 — Benchmarking | Full Criterion suite, comparative report | ⏳ Planned |
| 6 — Docs & Publication | `crates.io` publish, mdBook, paper | ⏳ Planned |
 
---

## Roadmap
 
- [ ] `BinaryMerkleTree<H>` with iterative construction and stateless proof verification
- [ ] `SparseMerkleTree<H>` with shortcut nodes and one-phase batch updates
- [ ] `MerklePatriciaTrie<H>` with RLP encoding, validated against Ethereum test vectors
- [ ] Full Criterion benchmark suite with comparative results vs `rs-merkle` and `merkle_light`
- [ ] mdBook user guide with copy-pasteable examples for each variant
- [ ] Publish `merkle-variants` to `crates.io`
- [ ] Research paper on benchmark findings and tree-type trade-off analysis

---

## Contributing
 
This project is currently closed to external contributions while active
development is underway as part of a final-year research project.
Watch this space for an announcement when contributions open.
 
Bug reports and feedback via GitHub Issues are always welcome.
 
---

## References

This library is informed by the following research:

- Kuznetsov et al. (2024) — Adaptive Merkle trees for enhanced blockchain scalability
- Ma et al. (2023) — One-phase batch update on sparse Merkle trees for rollups
- Dahlberg et al. (2016) — Efficient sparse Merkle trees: caching strategies and secure proofs
- Buterin, V. (2018) — Optimizing sparse Merkle trees
- Ouvrard, P. A. (2018/2019) — Sparse Merkle tree performance-oriented implementations
- Wood, G. (2014) — Ethereum Yellow Paper

Full bibliography in the accompanying research proposal.

---

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

---

*Developed by [Blessing Samuel](https://github.com/dicethedev)*
