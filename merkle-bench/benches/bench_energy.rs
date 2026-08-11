//! Energy-aware construction benchmark.
//!
//! Criterion records wall-clock timing for constructing a 100,000-leaf binary
//! Merkle tree with each supported hash adapter. CPU cycles and package energy
//! are collected by running this benchmark through `scripts/energy-perf.sh`.
//!
//! ```bash
//! cargo bench --bench bench_energy
//! ./scripts/energy-perf.sh bench_energy
//! ```

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use merkle_core::traits::HashFunction;
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::{Blake3, Keccak256, Sha256};
use std::hint::black_box;
use std::path::Path;
use std::time::Duration;

const LEAF_COUNT: usize = 100_000;

fn leaf_data() -> Vec<[u8; 32]> {
    (0..LEAF_COUNT)
        .map(|index| {
            let mut leaf = [0_u8; 32];
            leaf[..8].copy_from_slice(&index.to_le_bytes());
            leaf[8..16].copy_from_slice(&(index.rotate_left(13)).to_le_bytes());
            leaf
        })
        .collect()
}

fn build_tree<H: HashFunction>(leaves: &[[u8; 32]]) -> BinaryMerkleTree<H> {
    let mut tree = BinaryMerkleTree::with_capacity(leaves.len());

    for leaf in leaves {
        tree.insert(leaf)
            .expect("benchmark leaves are always non-empty");
    }

    black_box(tree)
}

fn bench_algorithm<H: HashFunction>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
) {
    let leaves = leaf_data();

    group.throughput(Throughput::Elements(LEAF_COUNT as u64));
    group.bench_with_input(
        BenchmarkId::new("construct_100k_leaves", name),
        &leaves,
        |bench, input| {
            bench.iter_batched(
                || input.clone(),
                |data| build_tree::<H>(black_box(&data)),
                BatchSize::LargeInput,
            );
        },
    );
}

fn energy_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_energy");

    bench_algorithm::<Sha256>(&mut group, "SHA-256");
    bench_algorithm::<Keccak256>(&mut group, "Keccak-256");
    bench_algorithm::<Blake3>(&mut group, "BLAKE3");

    group.finish();
}

fn benchmark_config() -> Criterion {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("merkle-bench must be inside the workspace");
    let output_directory = workspace_root.join("target/criterion");

    Criterion::default()
        .output_directory(&output_directory)
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = energy_benchmarks
}
criterion_main!(benches);
