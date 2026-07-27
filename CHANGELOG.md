# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Workspace note:** `merkle-core`, `merkleforge-hash`, and `merkle-variants` are
> versioned together. A single entry here covers all published crates unless
> stated otherwise. `merkle-bench` is never published (`publish = false`).

---

## [Unreleased]

No unreleased changes yet.

---

## [0.4.0] — 2026-07-27

Phase 4 complete: Ethereum-compatible Merkle Patricia Trie implementation and
release.

### Added — `merkle-variants`

- `MerklePatriciaTrie<H>` with Ethereum-style empty, leaf, extension, and
  branch node variants over nibble-addressed keys
- `NibblePath` utilities for converting byte keys into 4-bit paths
- Hex-prefix path encoding and decoding for leaf and extension nodes
- Recursive Length Prefix encoding and decoding for all Patricia trie node
  variants
- Ethereum node reference handling with inline RLP for small nodes and
  `H(RLP(node))` references for larger nodes
- Key-value insertion, lookup, removal, and canonical node collapsing
- EIP-1186-style `MptProof<D>` membership and non-membership witnesses
- Stateless MPT proof verification against a trusted root
- Official Ethereum trie vector validation for `trietest.json`,
  `trieanyorder.json`, and the canonical empty trie root
- Property-based tests covering insertion retrieval, removal correctness,
  root sensitivity, key independence, order independence, proof completeness,
  RLP round-trips, and proof serialization
- Criterion benchmark coverage for Patricia insertion, lookup, proof
  generation, proof verification, and state-root construction across
  Keccak-256 and BLAKE3
- `MerkleTree<H>` implementation for generic Patricia trie root, count,
  height, insertion, removal, and metadata access with
  `variant = "MerklePatriciaTrie"`

- `SparseMerkleTree<H>` with a fixed 256-bit key space and precomputed
  empty-hash cache for all levels
- Key-addressed sparse insertion, removal, lookup, membership proof, and
  non-membership proof APIs
- `MerkleTree<H>` implementation for generic sparse tree usage with
  `variant = "SparseMerkleTree"` metadata
- Shortcut-node compression for single-leaf subtrees, following the Buterin
  sparse Merkle tree optimisation
- Batched terminal subtrees for reduced materialized node count
- One-phase-style `batch_insert` and `batch_remove` APIs for rollup-oriented
  update workloads
- Property-based tests covering root sensitivity, commutativity, proof
  round-trips, non-membership, remove soundness, batch equivalence, and proof
  serialization
- Criterion benchmark coverage for sparse inserts, proof generation, proof
  verification, non-membership, and batch updates across SHA-256, Keccak-256,
  and BLAKE3

### Changed

- Workspace crate version advanced to `0.3.0`
- Sparse tree docs now include the generic `MerkleTree<H>` contract alongside
  the native key-addressed API

### Documentation

- Added a crate-specific `merkle-variants` README for crates.io and docs.rs.

### Website

- Replaced the benchmark-only landing page with the official MerkleForge site.
- Added dedicated documentation, examples, benchmark, and Criterion report
  sections under a maintainable `website/` source directory.

### Planned — Phase 5 (Weeks 9–10)
- Full Criterion benchmark suite at 100 / 1 000 / 10 000 / 100 000 / 1 000 000 leaves
- Metrics: construction latency, proof generation latency, proof size (bytes), peak memory usage
- Comparative results vs `rs-merkle` and `merkle_light`
- HTML benchmark reports committed to `benches/reports/`

### Planned — Phase 6 (Weeks 11–12)
- Complete rustdoc coverage with copy-pasteable examples for all public items
- mdBook user guide at `docs/`
- Research paper draft on benchmark findings and tree-type trade-offs

---

## [0.2.0] — 2026-06-15

Phase 2 complete: binary Merkle tree implementation and release preparation.

### Added — `merkle-variants`

- `BinaryMerkleTree<H>` with flat, cache-friendly node storage and automatic
  power-of-two padding
- `MerkleTree<H>` implementation covering insertion, removal, root queries,
  leaf count, height, proof generation, and metadata
- `ProofVerifier<H>` implementation for stateless inclusion-proof validation
- Metadata reporting with `variant = "BinaryMerkleTree"` and the algorithm
  name supplied by `H::algorithm_name()`
- Unit, integration, property-based, and Criterion benchmark coverage across
  SHA-256, Keccak-256, and BLAKE3
- Copy-pasteable rustdoc example for tree construction and proof verification

### Changed

- Workspace crate version advanced to `0.2.0`
- Removing from an empty binary tree now returns `MerkleError::EmptyTree` as
  required by the `MerkleTree` trait contract

---

## [0.1.0] — 2026-03-09
## [0.1.1] — 2026-03-09

### Fixed
- Edited merkle-lib to MerkleForge Folder name

Phase 1 complete: core infrastructure. Establishes the entire foundation
the workspace builds on — trait hierarchy, type system, hash adapters, error
handling, benchmarking scaffold, and CI/CD pipeline.

### Added — `merkle-core`

**Traits (`merkle_core::traits`)**

- `HashFunction` trait — pluggable cryptographic abstraction parameterising
  every tree type over `H: HashFunction`; associated type `Digest` must satisfy
  `AsRef<[u8]> + Clone + Debug + PartialEq + Eq + Send + Sync + 'static`;
  provided methods `hash_nodes` (default: concatenate then hash) and `empty`
  (default: `hash(&[])`) are both overridable
- `MerkleTree<H: HashFunction>` trait — universal interface across all tree
  variants; mandates `insert`, `remove`, `root`, `leaf_count`, `height`,
  `generate_proof`, and `metadata`; provides `is_empty` as a default
- `ProofVerifier<H: HashFunction>` trait — stateless inclusion-proof
  verification requiring only a root hash and a `MerkleProof`; deliberately
  separate from `MerkleTree` so it can be implemented on a zero-sized struct
  with no tree allocation (light-client model)
- `Serializable` trait — blanket implementation over all
  `serde::Serialize + DeserializeOwned` types using `bincode`; covers
  `MerkleProof<D>` and `TreeMetadata` with no extra derives; exposes
  `to_bytes`, `from_bytes`, and `serialized_size`

**Types (`merkle_core::types`)**

- `LeafIndex(usize)` — strongly-typed leaf-layer index; convertible to
  `NodeIndex` via `From` but not vice-versa, preventing index misuse at
  compile time
- `NodeIndex(usize)` — strongly-typed node-array index; `NodeIndex::root(n)`
  computes the root position as `2n - 1` for a power-of-two flat layout
- `ProofSide` enum — `Left` / `Right` variants indicating which side a
  sibling occupies during proof-path traversal
- `ProofNode<D>` struct — a single proof-path step: `hash: D` (the sibling
  digest) and `side: ProofSide`
- `MerkleProof<D>` struct — complete inclusion proof: `leaf_index`,
  `leaf_count`, and `path: Vec<ProofNode<D>>`; provides `depth()` and
  `is_trivial()` helpers; fully `serde`-serialisable
- `TreeMetadata` struct — lightweight diagnostic snapshot: `leaf_count`,
  `height`, `node_count`, `hash_algorithm: &'static str`,
  `variant: &'static str`

**Error handling (`merkle_core::error`)**

- `MerkleError` enum — unified `#[non_exhaustive]` error type returned by
  every fallible function in the workspace; variants:
  `EmptyTree`, `IndexOutOfBounds { index, len }`, `InvalidProof`,
  `InvalidProofStructure(String)`, `EmptyLeafData`,
  `SerializationError(String)`, `DeserializationError(String)`,
  `HashError(String)`, `UnsupportedOperation(&'static str)`,
  `RlpError(String)`
- `impl std::error::Error for MerkleError`
- `impl From<bincode::Error> for MerkleError` → `SerializationError`

**Prelude**

- `merkle_core::prelude` re-exports `MerkleError`, all four traits, and all
  six public types for single-line glob import

---

### Added — `merkleforge-hash`

- `Sha256` — SHA-256 adapter; leaf hashing `SHA-256(0x00 || data)`;
  node hashing `SHA-256(0x01 || left || right)`; `empty()` returns the
  pre-computed sentinel `SHA-256(0x00)` to avoid repeated runtime hashing;
  hardware-accelerated on x86-64 via the `sha2` crate's compile-time
  SHA-extension and AVX2 detection
- `Keccak256` — Keccak-256 adapter backed by `tiny-keccak`; produces digests
  identical to `web3.utils.keccak256` and Solidity's `keccak256()` built-in;
  **not** NIST SHA-3 (different padding); correct choice for any tree
  whose roots must be verifiable by Ethereum tooling
- `Blake3` — BLAKE3 adapter using `blake3::derive_key` for domain separation;
  leaf context `"MerkleForge 2024 leaf v1"`; node context
  `"MerkleForge 2024 internal-node v1"`; eliminates the need for prefix bytes
  and removes any length-extension risk at domain boundaries
- All three adapters are `Copy + Clone + Debug + PartialEq + Eq`
- `merkleforge_hash::HashFunction` re-export for single-crate imports
- `#[forbid(unsafe_code)]` enforced at crate root

---

### Added — `merkle-bench`

- `baseline_construction` benchmark — measures leaf-hash and node-hash
  latency for SHA-256, Keccak-256, and BLAKE3 across input sizes
  32 / 64 / 128 / 256 / 512 bytes using `criterion::BenchmarkId`;
  reports `Throughput::Bytes` so Criterion converts results to MB/s
- `hash_throughput` benchmark — measures sustained hashing throughput at
  1 KB / 16 KB / 64 KB / 1 MB buffer sizes across all three adapters;
  provides the raw per-algorithm ceiling that tree construction cannot exceed
- Both benchmarks use `criterion::black_box` to prevent compiler
  dead-code elimination from skewing results
- HTML reports enabled via `criterion` `html_reports` feature

---

### Added — CI/CD

- GitHub Actions workflow at `.github/workflows/ci.yml`
- `test` job: runs `cargo build` and `cargo test` on both `stable` and
  `beta` Rust toolchains; caches `~/.cargo/registry`, `~/.cargo/git`,
  and `target/` keyed on `Cargo.lock` hash
- `lint` job: `cargo fmt --check` and `cargo clippy --pedantic`
  with `-D warnings`; runs on `stable` only
- `bench-dry` job: `cargo bench --no-run` — ensures benchmarks compile
  on every push without paying the runtime cost in CI
- `docs` job: `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"` —
  fails on broken intra-doc links or missing `///` items
- `RUSTFLAGS="-D warnings"` set globally; all warnings are build failures

---

### Security

- Domain separation enforced in all three hash adapters: leaf inputs are
  prefixed with `0x00` (or a leaf-context string for BLAKE3); internal-node
  inputs are prefixed with `0x01` (or a node-context string); prevents
  the RFC 6962 second-preimage attack where an attacker substitutes an
  internal node for a leaf in a proof
- `#[forbid(unsafe_code)]` on `merkle-core` and `merkleforge-hash`; no unsafe
  blocks anywhere in the workspace
- `MerkleError` is `#[non_exhaustive]`; downstream `match` expressions
  require a catch-all arm, making them forward-compatible with new variants
  added in minor releases

---

[Unreleased]: https://github.com/dicethedev/MerkleForge/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/dicethedev/MerkleForge/compare/v0.2.0...v0.4.0
[0.2.0]: https://github.com/dicethedev/MerkleForge/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/dicethedev/MerkleForge/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dicethedev/MerkleForge/releases/tag/v0.1.0