//! Comparative benchmarks against external Merkle tree crates.
//!
//! Run with:
//! ```bash
//! cargo bench --bench comparison
//! ```

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use merkle_core::{traits::Serializable, types::LeafIndex};
use merkle_light::{hash::Algorithm as LightAlgorithm, merkle::MerkleTree as LightMerkleTree};
use merkle_variants::BinaryMerkleTree as ForgeMerkleTree;
use merkleforge_hash::Sha256 as ForgeSha256;
use rs_merkle::{Hasher as RsHasher, MerkleTree as RsMerkleTree, algorithms::Sha256 as RsSha256};
use sha2::{Digest as Sha2Digest, Sha256 as Sha2_256};
use std::{hash::Hasher, hint::black_box, path::Path, time::Duration};

const LEAF_COUNT: usize = 10_000;
const PROOF_INDEX: usize = LEAF_COUNT / 2;

#[derive(Clone, Default)]
struct LightSha256(Sha2_256);

impl Hasher for LightSha256 {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

impl LightAlgorithm<[u8; 32]> for LightSha256 {
    fn hash(&mut self) -> [u8; 32] {
        self.0.finalize_reset().into()
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

fn leaf_data() -> Vec<[u8; 32]> {
    (0..LEAF_COUNT)
        .map(|index| {
            let mut leaf = [0_u8; 32];
            leaf[..8].copy_from_slice(&index.to_le_bytes());
            leaf[8..16].copy_from_slice(&(index.rotate_left(7)).to_le_bytes());
            leaf
        })
        .collect()
}

fn forge_tree(leaves: &[[u8; 32]]) -> ForgeMerkleTree<ForgeSha256> {
    let mut tree = ForgeMerkleTree::with_capacity(leaves.len());
    for leaf in leaves {
        tree.insert(leaf)
            .expect("comparison leaves are always non-empty");
    }
    tree
}

fn rs_leaves(leaves: &[[u8; 32]]) -> Vec<<RsSha256 as RsHasher>::Hash> {
    leaves.iter().map(|leaf| RsSha256::hash(leaf)).collect()
}

fn rs_tree(leaves: &[[u8; 32]]) -> RsMerkleTree<RsSha256> {
    RsMerkleTree::<RsSha256>::from_leaves(&rs_leaves(leaves))
}

fn light_tree(leaves: &[[u8; 32]]) -> LightMerkleTree<[u8; 32], LightSha256> {
    leaves.iter().copied().collect()
}

fn comparison_benchmarks(c: &mut Criterion) {
    let leaves = leaf_data();
    let rs_hashed_leaves = rs_leaves(&leaves);

    let forge = forge_tree(&leaves);
    let forge_proof = forge
        .generate_proof(LeafIndex(PROOF_INDEX))
        .expect("proof index exists");
    let forge_root = *forge.root().expect("comparison tree is non-empty");
    let forge_leaf = leaves[PROOF_INDEX];

    let rs = RsMerkleTree::<RsSha256>::from_leaves(&rs_hashed_leaves);
    let rs_proof = rs.proof(&[PROOF_INDEX]);
    let rs_root = rs.root().expect("comparison tree is non-empty");
    let rs_leaf = rs_hashed_leaves[PROOF_INDEX];

    let light = light_tree(&leaves);
    let light_proof = light.gen_proof(PROOF_INDEX);

    let forge_proof_size = forge_proof.to_bytes().expect("serializes").len();
    let rs_proof_size = rs_proof.to_bytes().len();
    let light_proof_size = light_proof.lemma().len() * 32;

    if std::env::var_os("MERKLEFORGE_PRINT_COMPARISON_SIZES").is_some() {
        eprintln!(
            "comparison proof sizes: MerkleForge={forge_proof_size} bytes, rs-merkle={rs_proof_size} bytes, merkle_light={light_proof_size} bytes"
        );
    }

    let mut construction = c.benchmark_group("comparison/construction_10k");
    construction.throughput(Throughput::Elements(LEAF_COUNT as u64));
    construction.bench_with_input(
        BenchmarkId::new("library", "MerkleForge"),
        &leaves,
        |b, input| {
            b.iter_batched(
                || input.clone(),
                |data| black_box(forge_tree(black_box(&data))),
                BatchSize::LargeInput,
            );
        },
    );
    construction.bench_with_input(
        BenchmarkId::new("library", "rs-merkle"),
        &leaves,
        |b, input| {
            b.iter_batched(
                || input.clone(),
                |data| black_box(rs_tree(black_box(&data))),
                BatchSize::LargeInput,
            );
        },
    );
    construction.bench_with_input(
        BenchmarkId::new("library", "merkle_light"),
        &leaves,
        |b, input| {
            b.iter_batched(
                || input.clone(),
                |data| black_box(light_tree(black_box(&data))),
                BatchSize::LargeInput,
            );
        },
    );
    construction.finish();

    let mut proof_size = c.benchmark_group("comparison/proof_size_bytes");
    proof_size.bench_function("MerkleForge", |b| {
        b.iter(|| black_box(forge_proof.to_bytes().expect("serializes").len()));
    });
    proof_size.bench_function("rs-merkle", |b| {
        b.iter(|| black_box(rs_proof.to_bytes().len()));
    });
    proof_size.bench_function("merkle_light", |b| {
        b.iter(|| black_box(light_proof.lemma().len() * 32));
    });
    proof_size.finish();

    let mut verification = c.benchmark_group("comparison/proof_verification");
    verification.bench_function("MerkleForge", |b| {
        b.iter(|| {
            black_box(ForgeMerkleTree::<ForgeSha256>::verify(
                black_box(&forge_root),
                black_box(&forge_leaf),
                black_box(&forge_proof),
            ));
        });
    });
    verification.bench_function("rs-merkle", |b| {
        b.iter(|| {
            black_box(rs_proof.verify(
                black_box(rs_root),
                black_box(&[PROOF_INDEX]),
                black_box(&[rs_leaf]),
                black_box(LEAF_COUNT),
            ));
        });
    });
    verification.bench_function("merkle_light", |b| {
        b.iter(|| {
            black_box(light_proof.validate::<LightSha256>());
        });
    });
    verification.finish();
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
    targets = comparison_benchmarks
}
criterion_main!(benches);
