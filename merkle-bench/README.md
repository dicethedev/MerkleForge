# merkle-bench

> Criterion benchmark suite for MerkleForge Framework.

`merkle-bench` is an internal workspace crate used for measurement only. It is
not published to crates.io. Keeping benchmarks isolated allows the project to
depend on comparison libraries and profiling tools without affecting the public
runtime crates.

## What It Measures

| Benchmark | Command | Measures |
| --- | --- | --- |
| Hash throughput | `cargo bench --bench hash_throughput` | SHA-256, Keccak-256, and BLAKE3 latency/throughput |
| Baseline construction | `cargo bench --bench baseline_construction` | Leaf hashing and internal-node combine costs |
| Binary tree | `cargo bench --bench binary_tree` | Construction, proof generation, and proof verification |
| Sparse tree | `cargo bench --bench sparse_tree` | Inserts, proofs, non-membership, and batch updates |
| Patricia trie | `cargo bench --bench patricia_trie` | Inserts, reads, proofs, verification, and root computation |
| Comparison | `cargo bench --bench comparison` | MerkleForge vs `rs-merkle` vs `merkle_light` |
| Energy-aware run | `cargo bench --bench bench_energy` | 100,000-leaf construction timing across hash adapters |

## Running Benchmarks

Run everything:

```bash
cargo bench --workspace
```

Run one benchmark target:

```bash
cargo bench --bench binary_tree
```

Criterion writes HTML reports to:

```text
target/criterion/
```

The website build copies those reports into the deployed GitHub Pages artifact
so the public dashboard can link to the raw Criterion output.

## Comparative Proof Sizes

The comparison benchmark can print serialized proof sizes:

```bash
MERKLEFORGE_PRINT_COMPARISON_SIZES=1 cargo bench --bench comparison -- --list
```

Use these numbers with the latency measurements in
[`BENCHMARKS.md`](../BENCHMARKS.md).

## Reporting Results

When publishing benchmark numbers, record:

- CPU model and core/thread count;
- RAM size;
- operating system and kernel;
- Rust version;
- command used;
- date of the run;
- whether the machine was on battery, plugged in, or thermally constrained.

Benchmark numbers are machine-dependent. Treat them as reproducible evidence
for a specific environment, not universal constants.

## Related Docs

- Benchmark summary: [`../BENCHMARKS.md`](../BENCHMARKS.md)
- Energy-aware runs: [`../benchmarks/ENERGY.md`](../benchmarks/ENERGY.md)
- Profiling guide: [`../profiling/README.md`](../profiling/README.md)
