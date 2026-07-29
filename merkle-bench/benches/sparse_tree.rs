//! Sparse Merkle tree benchmarks.
//!
//! Run with:
//! ```bash
//! cargo bench --bench sparse_tree
//! ```
//!
//! Reports are written below `target/criterion/sparse_tree/`.

use std::{hint::black_box, path::Path, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use merkle_core::traits::HashFunction;
use merkle_variants::{SparseMerkleTree, sparse::SparseMerkleProof};
use merkleforge_hash::{Blake3, Keccak256, Sha256};

const EXISTING_SIZES: &[usize] = &[10, 100, 1_000, 10_000];
const BATCH_SIZES: &[usize] = &[10, 100, 1_000];
const INSERT_DOMAIN: u8 = 0x11;
const PROOF_DOMAIN: u8 = 0x22;
const BATCH_DOMAIN: u8 = 0x33;
const MISSING_DOMAIN: u8 = 0xEE;

struct MembershipFixture<H: HashFunction> {
    tree: SparseMerkleTree<H>,
    key: [u8; 32],
    value: Vec<u8>,
    root: H::Digest,
    proof: SparseMerkleProof<H::Digest>,
}

struct NonMembershipFixture<H: HashFunction> {
    tree: SparseMerkleTree<H>,
    key: [u8; 32],
    root: H::Digest,
    proof: SparseMerkleProof<H::Digest>,
}

fn key(domain: u8, index: usize) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[0] = domain;
    key[8..16].copy_from_slice(&(index as u64).to_be_bytes());
    key[24..32].copy_from_slice(&(!index as u64).to_be_bytes());
    key
}

fn value(domain: u8, index: usize) -> Vec<u8> {
    let mut value = Vec::with_capacity(33);
    value.push(domain);
    value.extend_from_slice(&(index as u64).to_be_bytes());
    value.extend_from_slice(&(index as u64).to_le_bytes());
    value.extend_from_slice(&[domain ^ 0xA5; 16]);
    value
}

fn updates(domain: u8, count: usize) -> Vec<([u8; 32], Vec<u8>)> {
    (0..count)
        .map(|index| (key(domain, index), value(domain, index)))
        .collect()
}

fn build_tree<H: HashFunction>(updates: &[([u8; 32], Vec<u8>)]) -> SparseMerkleTree<H> {
    let mut tree = SparseMerkleTree::new();
    tree.batch_insert(updates)
        .expect("benchmark updates are always non-empty");
    tree
}

fn root<H: HashFunction>(tree: &SparseMerkleTree<H>) -> H::Digest {
    tree.root().expect("benchmark tree is non-empty").clone()
}

fn proof_fixture<H: HashFunction>(size: usize) -> MembershipFixture<H> {
    let updates = updates(PROOF_DOMAIN, size);
    let tree = build_tree::<H>(&updates);
    let proof_key = key(PROOF_DOMAIN, size / 2);
    let proof_value = value(PROOF_DOMAIN, size / 2);
    let proof = tree
        .generate_membership_proof(proof_key)
        .expect("proof key exists");
    let root = root(&tree);

    MembershipFixture {
        tree,
        key: proof_key,
        value: proof_value,
        root,
        proof,
    }
}

fn non_membership_fixture<H: HashFunction>(size: usize) -> NonMembershipFixture<H> {
    let updates = updates(PROOF_DOMAIN, size);
    let tree = build_tree::<H>(&updates);
    let missing_key = key(MISSING_DOMAIN, size);
    let proof = tree
        .generate_membership_proof(missing_key)
        .expect("missing keys still produce non-membership proofs");
    let root = root(&tree);

    NonMembershipFixture {
        tree,
        key: missing_key,
        root,
        proof,
    }
}

fn bench_sparse_insert_for<H: HashFunction>(c: &mut Criterion, algorithm: &str) {
    let mut group = c.benchmark_group("sparse_tree/insert");

    for &size in EXISTING_SIZES {
        let existing = updates(INSERT_DOMAIN, size);
        let insert_key = key(INSERT_DOMAIN, size);
        let insert_value = value(INSERT_DOMAIN, size);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new(algorithm, size),
            &(existing, insert_key, insert_value),
            |b, (existing, insert_key, insert_value)| {
                b.iter_batched(
                    || build_tree::<H>(existing),
                    |mut tree| {
                        tree.insert(black_box(*insert_key), black_box(insert_value))
                            .expect("benchmark insert data is non-empty");
                        black_box(tree.root().cloned())
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_sparse_proof_generation_for<H: HashFunction>(c: &mut Criterion, algorithm: &str) {
    let mut group = c.benchmark_group("sparse_tree/proof_generation");

    for &size in EXISTING_SIZES {
        let fixture = proof_fixture::<H>(size);

        group.bench_with_input(BenchmarkId::new(algorithm, size), &fixture, |b, fixture| {
            b.iter(|| {
                black_box(
                    fixture
                        .tree
                        .generate_membership_proof(black_box(fixture.key))
                        .expect("proof key exists"),
                )
            });
        });
    }

    group.finish();
}

fn bench_sparse_proof_verification_for<H: HashFunction>(c: &mut Criterion, algorithm: &str) {
    let mut group = c.benchmark_group("sparse_tree/proof_verification");

    for &size in EXISTING_SIZES {
        let fixture = proof_fixture::<H>(size);

        group.bench_with_input(BenchmarkId::new(algorithm, size), &fixture, |b, fixture| {
            b.iter(|| {
                black_box(SparseMerkleTree::<H>::verify(
                    black_box(&fixture.root),
                    black_box(&fixture.value),
                    black_box(&fixture.proof),
                ))
            });
        });
    }

    group.finish();
}

fn bench_sparse_non_membership_for<H: HashFunction>(c: &mut Criterion, algorithm: &str) {
    {
        let mut generation = c.benchmark_group("sparse_tree/non_membership_generation");

        for &size in EXISTING_SIZES {
            let fixture = non_membership_fixture::<H>(size);

            generation.bench_with_input(
                BenchmarkId::new(algorithm, size),
                &fixture,
                |b, fixture| {
                    b.iter(|| {
                        black_box(
                            fixture
                                .tree
                                .generate_membership_proof(black_box(fixture.key))
                                .expect("missing keys still produce non-membership proofs"),
                        )
                    });
                },
            );
        }

        generation.finish();
    }

    {
        let mut verification = c.benchmark_group("sparse_tree/non_membership_verification");

        for &size in EXISTING_SIZES {
            let fixture = non_membership_fixture::<H>(size);

            verification.bench_with_input(
                BenchmarkId::new(algorithm, size),
                &fixture,
                |b, fixture| {
                    b.iter(|| {
                        black_box(SparseMerkleTree::<H>::verify_non_membership(
                            black_box(&fixture.root),
                            black_box(fixture.key),
                            black_box(&fixture.proof),
                        ))
                    });
                },
            );
        }

        verification.finish();
    }
}

fn bench_sparse_batch_update_for<H: HashFunction>(c: &mut Criterion, algorithm: &str) {
    let mut group = c.benchmark_group("sparse_tree/batch_update");

    for &size in BATCH_SIZES {
        let batch = updates(BATCH_DOMAIN, size);

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new(format!("{algorithm}/batch_insert"), size),
            &batch,
            |b, batch| {
                b.iter_batched(
                    SparseMerkleTree::<H>::new,
                    |mut tree| {
                        tree.batch_insert(black_box(batch))
                            .expect("benchmark batch data is non-empty");
                        black_box(tree.root().cloned())
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new(format!("{algorithm}/sequential_insert"), size),
            &batch,
            |b, batch| {
                b.iter_batched(
                    SparseMerkleTree::<H>::new,
                    |mut tree| {
                        for (key, value) in batch {
                            tree.insert(black_box(*key), black_box(value))
                                .expect("benchmark insert data is non-empty");
                        }
                        black_box(tree.root().cloned())
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn sparse_tree_benchmarks(c: &mut Criterion) {
    bench_sparse_insert_for::<Sha256>(c, "SHA-256");
    bench_sparse_insert_for::<Keccak256>(c, "Keccak-256");
    bench_sparse_insert_for::<Blake3>(c, "BLAKE3");

    bench_sparse_proof_generation_for::<Sha256>(c, "SHA-256");
    bench_sparse_proof_generation_for::<Keccak256>(c, "Keccak-256");
    bench_sparse_proof_generation_for::<Blake3>(c, "BLAKE3");

    bench_sparse_proof_verification_for::<Sha256>(c, "SHA-256");
    bench_sparse_proof_verification_for::<Keccak256>(c, "Keccak-256");
    bench_sparse_proof_verification_for::<Blake3>(c, "BLAKE3");

    bench_sparse_non_membership_for::<Sha256>(c, "SHA-256");
    bench_sparse_non_membership_for::<Keccak256>(c, "Keccak-256");
    bench_sparse_non_membership_for::<Blake3>(c, "BLAKE3");

    bench_sparse_batch_update_for::<Sha256>(c, "SHA-256");
    bench_sparse_batch_update_for::<Keccak256>(c, "Keccak-256");
    bench_sparse_batch_update_for::<Blake3>(c, "BLAKE3");
}

fn benchmark_config() -> Criterion {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("merkle-bench must be inside the workspace");
    let output_directory = workspace_root.join("target/criterion");

    Criterion::default()
        .output_directory(&output_directory)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = sparse_tree_benchmarks
}
criterion_main!(benches);
