//! Binary Merkle tree construction and proof benchmarks.
//!
//! Run with:
//! ```bash
//! cargo bench --bench binary_tree
//! ```
//!
//! Reports are written below `target/criterion/binary_tree/`.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use merkle_core::traits::HashFunction;
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::{Blake3, Keccak256, Sha256};
use std::hint::black_box;
use std::path::Path;
use std::time::Duration;

const TREE_SIZES: &[usize] = &[100, 1_000, 10_000, 100_000];

fn leaf_data(count: usize) -> Vec<[u8; 32]> {
    (0..count)
        .map(|index| {
            let mut leaf = [0u8; 32];
            leaf[..8].copy_from_slice(&index.to_le_bytes());
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
    tree
}

fn bench_algorithm<H: HashFunction>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
) {
    for &size in TREE_SIZES {
        let leaves = leaf_data(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new(format!("construction/{name}"), size),
            &leaves,
            |b, input| {
                b.iter_batched(
                    || input,
                    |data| black_box(build_tree::<H>(black_box(data))),
                    BatchSize::SmallInput,
                );
            },
        );

        let tree = build_tree::<H>(&leaves);
        group.bench_with_input(
            BenchmarkId::new(format!("proof_generation/{name}"), size),
            &tree,
            |b, tree| {
                b.iter(|| {
                    black_box(
                        tree.generate_proof(black_box(merkle_core::types::LeafIndex(0)))
                            .expect("leaf zero exists"),
                    )
                });
            },
        );

        let proof = tree
            .generate_proof(merkle_core::types::LeafIndex(0))
            .expect("leaf zero exists");
        let root = tree.root().expect("benchmark tree is non-empty").clone();
        let first_leaf = leaves[0];
        group.bench_with_input(
            BenchmarkId::new(format!("proof_verification/{name}"), size),
            &(root, proof, first_leaf),
            |b, (root, proof, leaf)| {
                b.iter(|| {
                    black_box(BinaryMerkleTree::<H>::verify(
                        black_box(root),
                        black_box(leaf),
                        black_box(proof),
                    ))
                });
            },
        );
    }
}

fn binary_tree_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("binary_tree");

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
        .measurement_time(Duration::from_secs(3))
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = binary_tree_benchmarks
}
criterion_main!(benches);
