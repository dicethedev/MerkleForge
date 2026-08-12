# Energy Benchmarking

MerkleForge measures normal latency with Criterion and measures CPU energy
externally with Linux performance tools. This keeps the Rust benchmark simple
while allowing the operating system to collect package-level counters.

The default energy workload builds a 100,000-leaf binary Merkle tree with
SHA-256, Keccak-256, and BLAKE3:

```bash
cargo bench --bench bench_energy
```

Criterion writes the wall-clock report to:

```text
target/criterion/bench_energy/
```

## Linux `perf` Method

On Intel and some AMD Linux machines, the kernel exposes RAPL energy counters
through the `power/*` performance monitoring unit. First check what your
machine supports:

```bash
perf list 'power/energy-*'
```

Then run the benchmark through the helper script:

```bash
./scripts/energy-perf.sh bench_energy
```

The script collects:

- `power/energy-pkg/` when available — package energy in Joules.
- `power/energy-cores/` and `power/energy-ram/` when available.
- `cycles`, `instructions`, `cache-references`, and `cache-misses`.
- `duration_time` for elapsed time observed by `perf`.

Some machines require elevated privileges or a relaxed perf policy:

```bash
sudo ./scripts/energy-perf.sh bench_energy
```

or:

```bash
sudo sysctl kernel.perf_event_paranoid=0
```

Use the privileged path only on a machine you control.

## Direct `perf` Command

For paper reproduction, this is the explicit command behind the script:

```bash
sudo perf stat -a -r 3 \
  -e cycles,instructions,cache-references,cache-misses,duration_time,power/energy-pkg/ \
  -- cargo bench --bench bench_energy
```

`-a` records across all CPUs. This matters for RAPL counters because package
energy is a socket-level reading, not a single-thread counter.

## Interpreting Results

Use the Criterion HTML report for latency and throughput. Use `perf stat` for
hardware counters:

- Lower `seconds time elapsed` means the construction finished sooner.
- Lower `power/energy-pkg/` Joules means the CPU package used less energy.
- Lower cycles for the same workload means less CPU work was needed.
- Cache misses help explain why two runs with similar hash speed may use
  different amounts of time or energy.

For Chapter 5, report the same machine, kernel, CPU governor, Rust version,
and command line next to every table. Energy measurements are hardware-specific,
so cross-machine comparisons should be treated as trends rather than absolute
truth.

## Results Table

Fill this table from the research benchmark machine after running
`./scripts/energy-perf.sh bench_energy`.

| Algorithm | Median wall time | Package energy | CPU cycles | Cache misses | Joules / 100k-leaf tree | Notes |
|-----------|------------------|----------------|------------|--------------|-------------------------|-------|
| SHA-256 | TBD | TBD | TBD | TBD | TBD | Run on research machine |
| Keccak-256 | TBD | TBD | TBD | TBD | TBD | Run on research machine |
| BLAKE3 | TBD | TBD | TBD | TBD | TBD | Run on research machine |

## Fallback: `turbostat`

If `perf list` does not show `power/energy-pkg/`, try `turbostat`:

```bash
sudo turbostat --Summary --Joules --out profiling/turbostat-energy.txt -- \
  cargo bench --bench bench_energy
```

`--Joules` reports energy totals instead of average Watts. This is useful on
systems where RAPL is available to turbostat but not exposed through perf.

## Fallback: `powertop`

`powertop` is less precise for per-benchmark measurement, but it can still
capture a repeatable system-level profile:

```bash
sudo powertop --time=60 --html=profiling/powertop-energy.html
```

Run the benchmark in another terminal while `powertop` samples. Use this only
as supporting evidence when `perf` and `turbostat` are unavailable.
