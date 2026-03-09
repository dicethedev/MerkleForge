//! # Hash throughput benchmark
//!
//! Measures sustained hashing throughput (MB/s) for each algorithm using
//! a large buffer.  This gives the raw "ceiling" that tree construction
//! can never exceed and directly corresponds to the comparative data
//! discussed in Section 2.5 of the proposal (AITCS, 2024 benchmarks).
//!
//! ## Running
//! ```bash
//! cargo bench --bench hash_throughput
//! ```

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use merkleforge_hash::{Blake3, HashFunction, Keccak256, Sha256};

const BUFFER_SIZES: &[usize] = &[
    1_024,     //  1 KB
    16_384,    // 16 KB
    65_536,    // 64 KB
    1_048_576, //  1 MB
];

fn throughput_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_throughput");

    for &size in BUFFER_SIZES {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("SHA-256", size), &data, |b, d| {
            b.iter(|| Sha256::hash(black_box(d)))
        });
        group.bench_with_input(BenchmarkId::new("Keccak-256", size), &data, |b, d| {
            b.iter(|| Keccak256::hash(black_box(d)))
        });
        group.bench_with_input(BenchmarkId::new("BLAKE3", size), &data, |b, d| {
            b.iter(|| Blake3::hash(black_box(d)))
        });
    }

    group.finish();
}

criterion_group!(benches, throughput_benchmarks);
criterion_main!(benches);
