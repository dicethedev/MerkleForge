# Profiling MerkleForge

> Reproducible CPU profiling notes and reference artifacts for MerkleForge
> Framework.

Criterion answers "how long did this operation take?" Profiling answers "where
did the CPU time go?" Use this directory when investigating construction,
proof-generation, hashing, memory-access, or trie traversal bottlenecks.

## Install Tools

Install the Rust flamegraph wrapper:

```bash
make install-profiling-tools
```

On Linux, `cargo-flamegraph` uses `perf`. Depending on your distribution, you
may need:

```bash
sudo apt install linux-tools-common linux-tools-generic
```

If kernel settings block profiling, temporarily lower the restriction:

```bash
sudo sysctl kernel.perf_event_paranoid=1
```

## Generate a Flamegraph

Run one benchmark target through the helper script:

```bash
./scripts/flamegraph.sh baseline_construction
```

The default output is:

```text
flamegraph.svg
```

Open the SVG in a browser and inspect the widest frames first. Wider frames
represent more sampled CPU time.

Useful benchmark targets:

```text
baseline_construction
hash_throughput
binary_tree
sparse_tree
patricia_trie
comparison
```

## Cache and Instruction Counters

Use `perf stat` when you need hardware-counter evidence:

```bash
perf stat -e cycles,instructions,cache-misses,cache-references \
  cargo bench --bench hash_throughput
```

For tree-specific analysis:

```bash
perf stat -e cycles,instructions,cache-misses,cache-references cargo bench --bench binary_tree
perf stat -e cycles,instructions,cache-misses,cache-references cargo bench --bench sparse_tree
perf stat -e cycles,instructions,cache-misses,cache-references cargo bench --bench patricia_trie
```

## Energy-Aware Runs

For processors that expose RAPL counters:

```bash
./scripts/energy-perf.sh bench_energy
```

See [`../benchmarks/ENERGY.md`](../benchmarks/ENERGY.md) for interpretation
notes and fallback tools such as `turbostat` or `powertop`.

## Reference Artifact

`profiling/flamegraph.svg` is a checked-in sample artifact showing the expected
shape and labeling of a profiling output. Regenerate a machine-specific
flamegraph before reporting performance numbers.
