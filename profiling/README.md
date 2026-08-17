# Profiling MerkleForge

This directory stores reproducible profiling notes and reference artifacts for
the research report. Criterion answers "how long did it take?"; profiling helps
answer "where did the CPU time go?"

## Install Tools

Install the Rust flamegraph wrapper:

```bash
make install-profiling-tools
```

On Linux, `cargo-flamegraph` uses `perf`. You may need system packages such as
`linux-tools`, `perf`, or `linux-tools-generic`, depending on your distribution.

If `perf` is blocked by kernel settings, temporarily lower the restriction:

```bash
sudo sysctl kernel.perf_event_paranoid=1
```

## Generate A Flamegraph

Run a single Criterion benchmark target through the helper script:

```bash
./scripts/flamegraph.sh baseline_construction
```

The default output is:

```text
flamegraph.svg
```

Open it in a browser and inspect the widest frames first. Wider frames represent
more sampled CPU time.

Useful benchmark names:

```text
baseline_construction
hash_throughput
binary_tree
sparse_tree
patricia_trie
```

## Cache-Miss Profiling

Use `perf stat` when the question is about cache behavior instead of call-stack
shape:

```bash
perf stat -e cache-misses,cache-references cargo bench --bench hash_throughput
```

For tree-specific analysis:

```bash
perf stat -e cycles,instructions,cache-misses,cache-references cargo bench --bench binary_tree
perf stat -e cycles,instructions,cache-misses,cache-references cargo bench --bench sparse_tree
perf stat -e cycles,instructions,cache-misses,cache-references cargo bench --bench patricia_trie
```

## Reference Artifact

`profiling/flamegraph.svg` is a checked-in sample artifact showing the expected
shape and labeling of a profiling output for Chapter 5 evidence. Regenerate a
machine-specific flamegraph before reporting final performance numbers.
