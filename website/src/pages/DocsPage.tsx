import { CodeWindow } from "../components/CodeWindow";
import { Footer } from "../components/Footer";
import { AppLayout } from "../layout/AppLayout";
import type { SiteData } from "../types/site";

const docsNav = [
  ["start", "Start"],
  ["install", "Install"],
  ["first-proof", "First proof"],
  ["mental-model", "Mental model"],
  ["choose-tree", "Choose a tree"],
  ["recipes", "Recipes"],
  ["reference", "Reference"],
  ["safety", "Safety"],
];

const startCards = [
  ["1", "Install the crates", "Add the core traits, hash adapters, and tree variants."],
  ["2", "Insert your data", "MerkleForge hashes each leaf and builds a compact root."],
  ["3", "Send a proof", "A verifier checks one value without seeing the whole dataset."],
];

const treeChoices = [
  [
    "BinaryMerkleTree",
    "Best for ordered lists",
    "Use this for transaction batches, file chunks, logs, and classic inclusion proofs.",
    "Small proof paths, simple indexing, fast to understand.",
  ],
  [
    "SparseMerkleTree",
    "Best for huge key spaces",
    "Use this when most keys are empty, like account maps, state slots, or rollup data.",
    "Membership and non-membership proofs from 32-byte keys.",
  ],
  [
    "MerklePatriciaTrie",
    "Best for Ethereum-style state",
    "Use this when you need nibble paths, RLP witnesses, and Keccak-compatible roots.",
    "Designed around Ethereum MPT behavior.",
  ],
];

export function DocsPage({ site }: { site: SiteData }) {
  return (
    <AppLayout page="docs" site={site}>
      <main className="docs-layout">
        <aside className="docs-nav">
          <span className="label">Docs</span>
          {docsNav.map(([id, label]) => (
            <a href={`#${id}`} key={id}>
              {label}
            </a>
          ))}
        </aside>

        <article className="docs-content friendly-docs">
          <section className="docs-hero-card" id="start">
            <span className="label">MerkleForge docs / v{site.crateVersion}</span>
            <h1>Build roots and verify proofs without carrying the whole tree.</h1>
            <p>
              MerkleForge is a Rust framework for authenticated data. You put data in, get a Merkle
              root out, and send small proofs that other apps can verify.
            </p>

            <div className="docs-hero-actions">
              <a className="button primary" href="#install">
                Start building
              </a>
              <a className="button secondary" href="https://docs.rs/merkle-core" target="_blank" rel="noreferrer">
                Rustdoc
              </a>
            </div>

            <div className="docs-start-grid">
              {startCards.map(([number, title, copy]) => (
                <div className="docs-start-card" key={title}>
                  <span>{number}</span>
                  <strong>{title}</strong>
                  <p>{copy}</p>
                </div>
              ))}
            </div>
          </section>

          <section id="install">
            <div className="docs-section-title">
              <span className="label">Step 1</span>
              <h2>Install the pieces you need.</h2>
              <p>
                Most apps should start with all three crates. They give you shared traits, official
                hash functions, and ready-made tree implementations.
              </p>
            </div>
            <CodeWindow
              file="Cargo.toml"
              meta="copy into your project"
              code={`[dependencies]
merkle-core = "${site.crateVersion}"
merkleforge-hash = "${site.crateVersion}"
merkle-variants = "${site.crateVersion}"`}
            />
            <div className="docs-note-grid">
              <div>
                <strong>Want only traits?</strong>
                <span>Use `merkle-core` when you are building your own tree or hash adapter.</span>
              </div>
              <div>
                <strong>Want Ethereum hashing?</strong>
                <span>Use `merkleforge-hash::Keccak256` with the Patricia trie.</span>
              </div>
            </div>
          </section>

          <section id="first-proof">
            <div className="docs-section-title">
              <span className="label">Step 2</span>
              <h2>Your first inclusion proof.</h2>
              <p>
                This is the core workflow: create a tree, insert values, generate a proof for one
                leaf, then verify it using only the root, proof, and original value.
              </p>
            </div>
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

    let root = tree.root().expect("tree has leaves");
    let proof = tree.generate_proof(LeafIndex(0))?;

    assert!(BinaryMerkleTree::<Sha256>::verify(
        root,
        b"alice:100",
        &proof,
    ));

    Ok(())
}`}
            />
            <div className="docs-result-card">
              <span>What just happened?</span>
              <p>
                The verifier did not need the tree. It only needed `root`, `proof`, and
                `b"alice:100"`. That is the light-client pattern.
              </p>
            </div>
          </section>

          <section id="mental-model">
            <div className="docs-section-title">
              <span className="label">Mental model</span>
              <h2>Think of a Merkle root as a fingerprint for many values.</h2>
              <p>
                If one leaf changes, the root changes. A proof is the short path that lets another
                machine check one value against that root.
              </p>
            </div>
            <div className="docs-model-grid">
              <article>
                <span>Input</span>
                <strong>Raw data</strong>
                <p>Transactions, balances, file chunks, account state, or any byte slice.</p>
              </article>
              <article>
                <span>Commitment</span>
                <strong>Merkle root</strong>
                <p>A compact digest that represents the whole dataset.</p>
              </article>
              <article>
                <span>Evidence</span>
                <strong>Proof</strong>
                <p>A small witness that proves one value belongs to that root.</p>
              </article>
            </div>
          </section>

          <section id="choose-tree">
            <div className="docs-section-title">
              <span className="label">Choose a tree</span>
              <h2>Pick the shape that matches your data.</h2>
              <p>
                You do not need to memorize all tree types. Start from the kind of data you have.
              </p>
            </div>
            <div className="docs-choice-grid">
              {treeChoices.map(([name, title, copy, detail]) => (
                <article className="docs-choice-card" key={name}>
                  <code>{name}</code>
                  <h3>{title}</h3>
                  <p>{copy}</p>
                  <small>{detail}</small>
                </article>
              ))}
            </div>
          </section>

          <section id="recipes">
            <div className="docs-section-title">
              <span className="label">Common recipes</span>
              <h2>Copy the pattern closest to your app.</h2>
            </div>

            <div className="docs-recipe">
              <div>
                <h3>Use a sparse tree for account-style state</h3>
                <p>Keys are 32 bytes. Missing keys can also be proven with non-membership proofs.</p>
              </div>
              <CodeWindow
                file="sparse_state.rs"
                meta="state map"
                code={`use merkle_variants::SparseMerkleTree;
use merkleforge_hash::Sha256;

let mut state = SparseMerkleTree::<Sha256>::new();
let alice = [7_u8; 32];

state.insert(alice, b"balance:100")?;

let root = state.root_hash();
let proof = state.generate_membership_proof(alice)?;

assert!(SparseMerkleTree::<Sha256>::verify(
    &root,
    b"balance:100",
    &proof,
));`}
              />
            </div>

            <div className="docs-recipe">
              <div>
                <h3>Use Patricia trie for Ethereum-style witnesses</h3>
                <p>Use Keccak-256 when you want Ethereum-compatible key-value state behavior.</p>
              </div>
              <CodeWindow
                file="patricia_state.rs"
                meta="Ethereum-style"
                code={`use merkle_variants::MerklePatriciaTrie;
use merkleforge_hash::Keccak256;

let mut trie = MerklePatriciaTrie::<Keccak256>::new();

trie.insert(b"account:alice", b"100")?;

let proof = trie.generate_proof(b"account:alice")?;
let root = trie.root_hash();

assert!(MerklePatriciaTrie::<Keccak256>::verify(
    &root,
    b"account:alice",
    b"100",
    &proof,
));`}
              />
            </div>

            <div className="docs-recipe">
              <div>
                <h3>Swap hash algorithms without changing tree logic</h3>
                <p>The hash choice is a type parameter, so there is no runtime switch.</p>
              </div>
              <CodeWindow
                file="hashes.rs"
                meta="type-level hash"
                code={`use merkle_variants::BinaryMerkleTree;
use merkleforge_hash::{Blake3, Keccak256, Sha256};

let sha_tree = BinaryMerkleTree::<Sha256>::new();
let eth_tree = BinaryMerkleTree::<Keccak256>::new();
let fast_tree = BinaryMerkleTree::<Blake3>::new();`}
              />
            </div>
          </section>

          <section id="reference">
            <div className="docs-section-title">
              <span className="label">Reference</span>
              <h2>The workspace is split into small crates.</h2>
            </div>
            <table>
              <thead>
                <tr>
                  <th>Crate</th>
                  <th>Use it for</th>
                  <th>Main items</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><code>merkle-core</code></td>
                  <td>Shared contracts, errors, proof types, and metadata.</td>
                  <td><code>MerkleTree</code>, <code>HashFunction</code>, <code>MerkleProof</code></td>
                </tr>
                <tr>
                  <td><code>merkleforge-hash</code></td>
                  <td>Official hash adapters.</td>
                  <td><code>Sha256</code>, <code>Keccak256</code>, <code>Blake3</code></td>
                </tr>
                <tr>
                  <td><code>merkle-variants</code></td>
                  <td>Ready-made tree implementations.</td>
                  <td><code>BinaryMerkleTree</code>, <code>SparseMerkleTree</code>, <code>MerklePatriciaTrie</code></td>
                </tr>
              </tbody>
            </table>
          </section>

          <section id="safety">
            <div className="docs-section-title">
              <span className="label">Safety status</span>
              <h2>Research software, tested carefully, not audited.</h2>
              <p>
                MerkleForge forbids unsafe Rust and includes unit, integration, property-based,
                documentation, and benchmark coverage. It has not received an independent
                cryptographic audit, so review carefully before production use.
              </p>
            </div>
          </section>
        </article>
      </main>
      <Footer right={<a href="https://docs.rs/merkle-core" target="_blank" rel="noreferrer">RUSTDOC</a>} />
    </AppLayout>
  );
}
