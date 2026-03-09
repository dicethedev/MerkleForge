//! # Baseline construction latency benchmark
//!
//! This benchmark measures the time to **hash a single leaf** using each of
//! the three supported hash adapters.  It corresponds to the "Baseline
//! Construction Latency Tests Configured" milestone shown in the Week 1-2
//! progress slide.
//!
//! Once `merkle-variants` crates are implemented (Phases 2-4) these
//! benchmarks will be extended to measure full tree construction,
//! proof generation, and proof verification at tree sizes:
//! 100 / 1 000 / 10 000 / 100 000 / 1 000 000 leaves.
//!
//! ## Running
//! ```bash
//! cargo bench --bench baseline_construction
//! ```
//! Reports are written to `target/criterion/baseline_construction/`.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use merkle_hash::{Blake3, HashFunction, Keccak256, Sha256};

// ── Leaf sizes to test (bytes) ─────────────────────────────────────────────

const LEAF_SIZES: &[usize] = &[32, 64, 128, 256, 512];

// ── Hash a single leaf ────────────────────────────────────────────────────

fn bench_sha256_leaf(c: &mut Criterion) {
    let mut group = c.benchmark_group("leaf_hash/SHA-256");
    for &size in LEAF_SIZES {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| Sha256::hash(black_box(d)));
        });
    }
    group.finish();
}

fn bench_keccak256_leaf(c: &mut Criterion) {
    let mut group = c.benchmark_group("leaf_hash/Keccak-256");
    for &size in LEAF_SIZES {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| Keccak256::hash(black_box(d)));
        });
    }
    group.finish();
}

fn bench_blake3_leaf(c: &mut Criterion) {
    let mut group = c.benchmark_group("leaf_hash/BLAKE3");
    for &size in LEAF_SIZES {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| Blake3::hash(black_box(d)));
        });
    }
    group.finish();
}

// ── Hash two nodes together (internal-node latency) ───────────────────────

fn bench_node_hashing(c: &mut Criterion) {
    let left = [0xABu8; 32];
    let right = [0xCDu8; 32];

    let mut group = c.benchmark_group("node_hash");
    group.throughput(Throughput::Bytes(64)); // 32 + 32 bytes input

    group.bench_function("SHA-256", |b| {
        b.iter(|| Sha256::hash_nodes(black_box(&left), black_box(&right)))
    });
    group.bench_function("Keccak-256", |b| {
        b.iter(|| Keccak256::hash_nodes(black_box(&left), black_box(&right)))
    });
    group.bench_function("BLAKE3", |b| {
        b.iter(|| Blake3::hash_nodes(black_box(&left), black_box(&right)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256_leaf,
    bench_keccak256_leaf,
    bench_blake3_leaf,
    bench_node_hashing,
);
criterion_main!(benches);
