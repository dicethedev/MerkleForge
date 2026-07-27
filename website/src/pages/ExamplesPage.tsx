import { CodeWindow } from "../components/CodeWindow";
import { Footer } from "../components/Footer";
import {
  exampleBuild,
  exampleDirectHash,
  exampleHashing,
  exampleMetadata,
  exampleSerialization,
  patriciaExample,
  sparseExample,
} from "../data/examples";
import { AppLayout } from "../layout/AppLayout";
import type { SiteData } from "../types/site";

const examples = [
  ["01", "Binary tree proof", "Insert a few leaves, generate an inclusion proof, and verify it against the root.", "binary_tree.rs", "SHA-256", "tree", exampleBuild],
  ["02", "Sparse state proof", "Use 32-byte keys for state-style data and prove a balance without sharing the whole map.", "sparse_state.rs", "SparseMerkleTree", "sparse", sparseExample],
  ["03", "Patricia witness", "Build Ethereum-style state with Keccak hashing, nibble paths, and witness verification.", "patricia_trie.rs", "Keccak-256", "patricia", patriciaExample],
  ["04", "Swap hash algorithms", "Keep the same tree API while choosing SHA-256, Keccak-256, or BLAKE3 at the type level.", "hash_adapters.rs", "Zero runtime dispatch", "hash", exampleHashing],
  ["05", "Hash directly", "Use the hash adapters outside a tree when building your own authenticated structure.", "direct_hash.rs", "Domain separated", "direct", exampleDirectHash],
  ["06", "Inspect metadata", "Read variant, hash algorithm, height, leaves, and allocated nodes for logs or dashboards.", "metadata.rs", "Diagnostics", "meta", exampleMetadata],
  ["07", "Transport a proof", "Serialize proof data so another process or service can verify the same evidence later.", "proof_transport.rs", "Serializable", "proof", exampleSerialization],
] as const;

const learningCards = [
  ["01", "Create roots", "Turn application data into a compact commitment."],
  ["02", "Send proofs", "Verify one value without sending the full dataset."],
  ["03", "Choose variants", "Use binary, sparse, or Patricia trees depending on your data."],
] as const;

export function ExamplesPage({ site }: { site: SiteData }) {
  return (
    <AppLayout page="examples" site={site}>
      <header className="page-hero examples-hero">
        <div>
          <h1>Copy a pattern, then make it yours.</h1>
          <p>
            These examples show the common MerkleForge flow in plain Rust: insert data, read the
            root, generate proof evidence, and verify it somewhere else. Every code block is
            copy-ready.
          </p>
        </div>
        <div className="examples-hero-art" aria-hidden="true">
          <span />
          <span />
          <span />
          <span />
        </div>
      </header>

      <main className="examples-page section">
        <div className="example-learning-grid">
          {learningCards.map(([number, title, copy]) => (
            <article className="example-learning-card" key={title}>
              <span>{number}</span>
              <strong>{title}</strong>
              <p>{copy}</p>
            </article>
          ))}
        </div>

        <div className="example-stack">
          {examples.map(([number, title, copy, file, meta, visual, code]) => (
            <article className="example-card" key={title}>
              <div className="example-copy">
                <span className="label">Example / {number}</span>
                <h2>{title}</h2>
                <p>{copy}</p>
                <div className={`example-mini-visual ${visual}`} aria-hidden="true">
                  <span />
                  <span />
                  <span />
                  <span />
                </div>
              </div>
              <CodeWindow file={file} meta={meta} code={code} />
            </article>
          ))}
        </div>
      </main>
      <Footer
        right={<a href={`${site.repositoryUrl}/tree/develop`} target="_blank" rel="noreferrer">SOURCE ↗</a>}
      />
    </AppLayout>
  );
}
