//! Merkle Patricia Trie benchmarks.
//!
//! Run with:
//! ```bash
//! cargo bench --bench patricia_trie
//! ```
//!
//! Reports are written below `target/criterion/patricia_trie/`.

use std::{hint::black_box, path::Path, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use merkle_core::traits::HashFunction;
use merkle_variants::{MerklePatriciaTrie, MptProof};
use merkleforge_hash::{Blake3, Keccak256};

const EXISTING_SIZES: &[usize] = &[10, 100, 1_000, 10_000];
const STATE_ROOT_SIZES: &[usize] = &[100, 1_000, 10_000];
const INSERT_DOMAIN: u8 = 0x11;
const GET_DOMAIN: u8 = 0x22;
const PROOF_DOMAIN: u8 = 0x33;
const ROOT_DOMAIN: u8 = 0x44;

struct GetFixture<H: HashFunction> {
    tree: MerklePatriciaTrie<H>,
    key: Vec<u8>,
}

struct ProofFixture<H: HashFunction> {
    tree: MerklePatriciaTrie<H>,
    key: Vec<u8>,
    root: H::Digest,
    proof: MptProof<H::Digest>,
}

fn key(domain: u8, index: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.push(domain);
    key.extend_from_slice(&(index as u64).to_be_bytes());
    key.extend_from_slice(&(index as u64).to_le_bytes());
    key.extend_from_slice(&(!index as u64).to_be_bytes());
    key.extend_from_slice(&[domain ^ 0xA5; 7]);
    key
}

fn value(domain: u8, index: usize) -> Vec<u8> {
    let mut value = Vec::with_capacity(33);
    value.push(domain);
    value.extend_from_slice(&(index as u64).to_be_bytes());
    value.extend_from_slice(&(index as u64).to_le_bytes());
    value.extend_from_slice(&[domain ^ 0x5A; 16]);
    value
}

fn updates(domain: u8, count: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..count)
        .map(|index| (key(domain, index), value(domain, index)))
        .collect()
}

fn build_tree<H>(updates: &[(Vec<u8>, Vec<u8>)]) -> MerklePatriciaTrie<H>
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    let mut tree = MerklePatriciaTrie::new();
    for (key, value) in updates {
        tree.insert(key, value)
            .expect("benchmark values are always non-empty");
    }

    tree
}

fn root<H>(tree: &MerklePatriciaTrie<H>) -> H::Digest
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    tree.root().expect("benchmark trie is non-empty").clone()
}

fn get_fixture<H>(size: usize) -> GetFixture<H>
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    let updates = updates(GET_DOMAIN, size);
    let tree = build_tree::<H>(&updates);
    let lookup_key = key(GET_DOMAIN, size / 2);

    GetFixture {
        tree,
        key: lookup_key,
    }
}

fn proof_fixture<H>(size: usize) -> ProofFixture<H>
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    let updates = updates(PROOF_DOMAIN, size);
    let tree = build_tree::<H>(&updates);
    let proof_key = key(PROOF_DOMAIN, size / 2);
    let proof = tree
        .generate_proof(&proof_key)
        .expect("proof key exists in benchmark trie");
    let root = root(&tree);

    ProofFixture {
        tree,
        key: proof_key,
        root,
        proof,
    }
}

fn bench_mpt_insert_for<H>(c: &mut Criterion, algorithm: &str)
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    let mut group = c.benchmark_group("patricia_trie/insert");

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
                        tree.insert(black_box(insert_key), black_box(insert_value))
                            .expect("benchmark insert value is non-empty");
                        black_box(tree.root().cloned())
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_mpt_get_for<H>(c: &mut Criterion, algorithm: &str)
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    let mut group = c.benchmark_group("patricia_trie/get");

    for &size in EXISTING_SIZES {
        let fixture = get_fixture::<H>(size);

        group.bench_with_input(BenchmarkId::new(algorithm, size), &fixture, |b, fixture| {
            b.iter(|| black_box(fixture.tree.get(black_box(&fixture.key))));
        });
    }

    group.finish();
}

fn bench_mpt_proof_generation_for<H>(c: &mut Criterion, algorithm: &str)
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    let mut group = c.benchmark_group("patricia_trie/proof_generation");

    for &size in EXISTING_SIZES {
        let fixture = proof_fixture::<H>(size);

        group.bench_with_input(BenchmarkId::new(algorithm, size), &fixture, |b, fixture| {
            b.iter(|| {
                black_box(
                    fixture
                        .tree
                        .generate_proof(black_box(&fixture.key))
                        .expect("proof key exists in benchmark trie"),
                )
            });
        });
    }

    group.finish();
}

fn bench_mpt_proof_verification_for<H>(c: &mut Criterion, algorithm: &str)
where
    H: HashFunction,
    H::Digest: From<[u8; 32]> + TryFrom<Vec<u8>>,
{
    let mut group = c.benchmark_group("patricia_trie/proof_verification");

    for &size in EXISTING_SIZES {
        let fixture = proof_fixture::<H>(size);

        group.bench_with_input(BenchmarkId::new(algorithm, size), &fixture, |b, fixture| {
            b.iter(|| {
                black_box(MerklePatriciaTrie::<H>::verify_proof(
                    black_box(&fixture.root),
                    black_box(&fixture.proof),
                ))
            });
        });
    }

    group.finish();
}

fn bench_mpt_state_root_for<H>(c: &mut Criterion, algorithm: &str)
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    let mut group = c.benchmark_group("patricia_trie/state_root");

    for &size in STATE_ROOT_SIZES {
        let entries = updates(ROOT_DOMAIN, size);

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new(algorithm, size), &entries, |b, entries| {
            b.iter_batched(
                || entries,
                |entries| {
                    let tree = build_tree::<H>(black_box(entries));
                    black_box(tree.root().cloned())
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn patricia_trie_benchmarks(c: &mut Criterion) {
    bench_mpt_insert_for::<Keccak256>(c, "Keccak-256");
    bench_mpt_insert_for::<Blake3>(c, "BLAKE3");

    bench_mpt_get_for::<Keccak256>(c, "Keccak-256");
    bench_mpt_get_for::<Blake3>(c, "BLAKE3");

    bench_mpt_proof_generation_for::<Keccak256>(c, "Keccak-256");
    bench_mpt_proof_generation_for::<Blake3>(c, "BLAKE3");

    bench_mpt_proof_verification_for::<Keccak256>(c, "Keccak-256");
    bench_mpt_proof_verification_for::<Blake3>(c, "BLAKE3");

    bench_mpt_state_root_for::<Keccak256>(c, "Keccak-256");
    bench_mpt_state_root_for::<Blake3>(c, "BLAKE3");
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
    targets = patricia_trie_benchmarks
}
criterion_main!(benches);
