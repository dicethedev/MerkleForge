# merkle-bench

> Criterion benchmark suite for MerkleForge hash adapters and tree variants.

This crate is intentionally isolated from the published runtime crates. It can
pull in comparison libraries, profiling helpers, and measurement-only code
without changing the public MerkleForge API.

## What It Measures

| Benchmark | Command | Purpose |
| --- | --- | --- |
| Hash throughput | `cargo bench --bench hash_throughput` | SHA-256, Keccak-256, and BLAKE3 latency/throughput |
| Baseline construction | `cargo bench --bench baseline_construction` | Raw leaf hashing and internal-node combine costs |
| Binary tree | `cargo bench --bench binary_tree` | Construction, proof generation, and proof verification |
| Sparse tree | `cargo bench --bench sparse_tree` | Inserts, proofs, non-membership, and batch updates |
| Patricia trie | `cargo bench --bench patricia_trie` | Inserts, reads, proofs, verification, and root computation |
| Comparison | `cargo bench --bench comparison` | MerkleForge vs `rs-merkle` vs `merkle_light` |
| Energy-aware run | `cargo bench --bench bench_energy` | 100,000-leaf construction timing for SHA-256, Keccak-256, and BLAKE3 |

## Run Everything

```bash
cargo bench --workspace
```

Criterion writes HTML reports under:

```text
target/criterion/
```

The official website copies those reports into the deployed Pages artifact so
the latest dashboard can link back to the raw Criterion output.

## Results Ledger

The human-readable benchmark tables live in the root
[`BENCHMARKS.md`](../BENCHMARKS.md). That file records:

- Benchmark environment and reproduction commands
- Hash function latency and throughput
- Binary, sparse, and Patricia tree measurements
- Energy-aware construction timings
- Comparative results against `rs-merkle` and `merkle_light`

Peak RSS memory capture is still tracked as the remaining Phase 5 evidence
item. Regenerate machine-specific numbers before using them in the research
paper or release notes.
