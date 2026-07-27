import { CodeWindow } from "../components/CodeWindow";
import { Footer } from "../components/Footer";
import { AppLayout } from "../layout/AppLayout";
import type { SiteData } from "../types/site";

const docsNav = [
  ["overview", "Overview"],
  ["installation", "Installation"],
  ["architecture", "Architecture"],
  ["first-tree", "First tree"],
  ["hashing", "Hash functions"],
  ["tree-variants", "Tree variants"],
  ["proofs", "Proofs"],
  ["metadata", "Metadata"],
  ["safety", "Safety status"],
];

export function DocsPage({ site }: { site: SiteData }) {
  return (
    <AppLayout page="docs" site={site}>
      <main className="docs-layout">
        <aside className="docs-nav">
          <span className="label">On this page</span>
          {docsNav.map(([id, label]) => (
            <a href={`#${id}`} key={id}>
              {label}
            </a>
          ))}
        </aside>
        <article className="docs-content">
          <section id="overview">
            <span className="label">Documentation / v{site.crateVersion}</span>
            <h1>Build proof-backed data structures in Rust.</h1>
            <p>
              MerkleForge helps you create Merkle roots, generate proofs, and verify data without
              rewriting the same tree logic for every project. Pick a hash function, pick a tree
              shape, then use one typed API across the workspace.
            </p>
            <div className="docs-callout-grid">
              <div className="docs-callout">
                <strong>Use it when</strong>
                <span>You need compact evidence that a value belongs to a dataset.</span>
              </div>
              <div className="docs-callout">
                <strong>Start simple</strong>
                <span>Install the crates, insert data, read the root, then verify proofs.</span>
              </div>
              <div className="docs-callout">
                <strong>Swap hashes</strong>
                <span>Choose SHA-256, Keccak-256, or BLAKE3 at the type level.</span>
              </div>
            </div>
          </section>
          <section id="installation">
            <h2>Installation</h2>
            <p>
              For most applications, install the full stack. This gives you shared traits, official
              hash adapters, and ready-made tree implementations.
            </p>
            <CodeWindow
              file="Cargo.toml"
              meta="crates.io"
              code={`[dependencies]\nmerkle-core = "${site.crateVersion}"\nmerkleforge-hash = "${site.crateVersion}"\nmerkle-variants = "${site.crateVersion}"`}
            />
            <p>
              If you already have your own hash adapter that implements <code>HashFunction</code>,
              you can skip <code>merkleforge-hash</code>.
            </p>
          </section>
          <section id="architecture">
            <h2>Architecture</h2>
            <p>
              The workspace is split so each crate has a clear job. This keeps small apps small and
              gives larger systems room to customize.
            </p>
            <table>
              <thead>
                <tr><th>Crate</th><th>Responsibility</th><th>Main API</th></tr>
              </thead>
              <tbody>
                <tr><td><code>merkle-core</code></td><td>Contracts and shared types</td><td><code>HashFunction</code>, <code>MerkleTree</code>, <code>MerkleProof</code></td></tr>
                <tr><td><code>merkleforge-hash</code></td><td>Cryptographic adapters</td><td><code>Sha256</code>, <code>Keccak256</code>, <code>Blake3</code></td></tr>
                <tr><td><code>merkle-variants</code></td><td>Concrete tree implementations</td><td><code>BinaryMerkleTree&lt;H&gt;</code>, <code>SparseMerkleTree&lt;H&gt;</code>, <code>MerklePatriciaTrie&lt;H&gt;</code></td></tr>
              </tbody>
            </table>
            <h3>Core traits</h3>
            <p>
              <code>HashFunction</code> tells a tree how to hash leaves, combine child nodes, produce
              an empty digest, and report its algorithm name. <code>MerkleTree&lt;H&gt;</code> gives each
              tree the same basic shape: insert data, read the root, generate proofs, and inspect
              metadata.
            </p>
          </section>
          <section id="first-tree">
            <h2>Your first tree</h2>
            <p>
              This example builds a binary tree, proves that the first leaf exists, then verifies the
              proof against the current root.
            </p>
            <CodeWindow
              file="src/main.rs"
              meta="BinaryMerkleTree<Sha256>"
              code={`use merkle_core::{traits::MerkleTree, types::LeafIndex};
use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::Sha256;

fn main() -> Result<(), merkle_core::error::MerkleError> {
    let mut tree = BinaryMerkleTree::<Sha256>::new();
    tree.insert(b"alice:100")?;
    tree.insert(b"bob:250")?;

    let proof = tree.generate_proof(LeafIndex(0))?;
    let root = tree.root().expect("tree has leaves");

    assert!(BinaryMerkleTree::<Sha256>::verify(
        root,
        b"alice:100",
        &proof,
    ));
    Ok(())
}`}
            />
          </section>
          <section id="hashing">
            <h2>Hash functions</h2>
            <p>
              Hash adapters are regular Rust types. Change the type parameter to change the
              algorithm, with no runtime switch in your tree code.
            </p>
            <table>
              <thead>
                <tr><th>Adapter</th><th>Algorithm</th><th>Typical use</th></tr>
              </thead>
              <tbody>
                <tr><td><code>Sha256</code></td><td>SHA-256</td><td>Widely interoperable authenticated data</td></tr>
                <tr><td><code>Keccak256</code></td><td>Keccak-256</td><td>Ethereum-compatible hashing</td></tr>
                <tr><td><code>Blake3</code></td><td>BLAKE3</td><td>High-throughput software hashing</td></tr>
              </tbody>
            </table>
            <CodeWindow
              file="src/hashes.rs"
              meta="type-level selection"
              code={`use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::{Blake3, Keccak256, Sha256};

let sha_tree = BinaryMerkleTree::<Sha256>::new();
let eth_tree = BinaryMerkleTree::<Keccak256>::new();
let fast_tree = BinaryMerkleTree::<Blake3>::new();`}
            />
          </section>
          <section id="tree-variants">
            <h2>Tree variants</h2>
            <p>
              Each tree fits a different data shape. Choose based on how your data is addressed and
              what kind of proof your users need.
            </p>
            <table>
              <thead>
                <tr><th>Variant</th><th>Status</th><th>Use case</th></tr>
              </thead>
              <tbody>
                <tr><td><code>BinaryMerkleTree&lt;H&gt;</code></td><td>Available in v{site.crateVersion}</td><td>Transaction batches, append-oriented datasets, SPV-style inclusion proofs</td></tr>
                <tr><td><code>SparseMerkleTree&lt;H&gt;</code></td><td>Available in v{site.crateVersion}</td><td>256-bit authenticated state, membership proofs, non-membership proofs, rollup-style batch updates</td></tr>
                <tr><td><code>MerklePatriciaTrie&lt;H&gt;</code></td><td>Available in v{site.crateVersion}</td><td>Ethereum-compatible state roots, RLP witnesses, nibble-addressed key-value state</td></tr>
              </tbody>
            </table>
            <p>
              All three variants expose root, count, height, and metadata through the shared
              <code>MerkleTree&lt;H&gt;</code> trait where that contract fits the tree model.
            </p>
          </section>
          <section id="proofs">
            <h2>Proof generation and verification</h2>
            <p>
              A proof is a small packet of evidence. Instead of sending the whole dataset, you send
              the value, the proof, and the expected root. The verifier recomputes the path and checks
              that it lands on the same root.
            </p>
            <CodeWindow
              file="proof shapes"
              meta="quick reference"
              code={`BinaryMerkleTree:       O(log n) proofs
SparseMerkleTree:       256-bit key path with shortcut and batch optimisations
MerklePatriciaTrie:     nibble-path traversal with RLP witness nodes`}
            />
          </section>
          <section id="metadata">
            <h2>Tree metadata</h2>
            <p>
              Use <code>metadata()</code> when you want to log what a tree contains or label benchmark
              output. It reports the variant, hash algorithm, leaf count, height, and allocated node
              count.
            </p>
            <CodeWindow
              file="src/metadata.rs"
              meta="introspection"
              code={`let metadata = tree.metadata();

println!("variant: {}", metadata.variant);
println!("hash: {}", metadata.hash_algorithm);
println!("leaves: {}", metadata.leaf_count);
println!("height: {}", metadata.height);
println!("nodes: {}", metadata.node_count);`}
            />
          </section>
          <section id="safety">
            <h2>Safety and project status</h2>
            <p>
              MerkleForge forbids unsafe Rust and includes unit, integration, property-based,
              documentation, and benchmark coverage. It is still research software and has not
              received an independent cryptographic audit, so review carefully before production use.
            </p>
          </section>
        </article>
      </main>
      <Footer right={<a href="https://docs.rs/merkle-core" target="_blank" rel="noreferrer">RUSTDOC ↗</a>} />
    </AppLayout>
  );
}
