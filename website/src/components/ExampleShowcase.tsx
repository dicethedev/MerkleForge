import { useState } from "react";
import { binaryExample, patriciaExample, sparseExample } from "../data/examples";
import { assetPath } from "../utils/paths";
import { CodeWindow } from "./CodeWindow";
import { ArrowUpRightIcon } from "./icons/ArrowUpRightIcon";

const examples = [
  {
    id: "binary",
    label: "Binary tree",
    title: "Create a root and prove one item.",
    description: "Use this when your data is a list: files, logs, blocks, or transactions.",
    file: "src/binary.rs",
    meta: "BinaryMerkleTree<Sha256>",
    code: binaryExample,
  },
  {
    id: "sparse",
    label: "Sparse state",
    title: "Prove a value inside a huge key space.",
    description: "Use this when keys are 32 bytes and most possible entries are empty.",
    file: "src/state.rs",
    meta: "SparseMerkleTree<Sha256>",
    code: sparseExample,
  },
  {
    id: "patricia",
    label: "Patricia trie",
    title: "Work with Ethereum-style state proofs.",
    description: "Use this for nibble paths, RLP nodes, and Ethereum-compatible witnesses.",
    file: "src/ethereum.rs",
    meta: "MerklePatriciaTrie<Keccak256>",
    code: patriciaExample,
  },
] as const;

export function ExampleShowcase() {
  const [activeId, setActiveId] = useState<(typeof examples)[number]["id"]>("binary");
  const active = examples.find((example) => example.id === activeId) ?? examples[0];

  return (
    <section className="example-showcase">
      <div className="example-panel">
        <span className="label">Quick start</span>
        <h2>See the tree, root, and proof in code.</h2>
        <p>
          Pick the shape that matches your data. Each example shows the same idea: insert data,
          read the root, generate proof evidence, and verify it.
        </p>
        <div className="example-tabs" role="tablist" aria-label="MerkleForge examples">
          {examples.map((example) => (
            <button
              className={example.id === active.id ? "example-tab active" : "example-tab"}
              key={example.id}
              type="button"
              onClick={() => setActiveId(example.id)}
            >
              {example.label}
            </button>
          ))}
        </div>
        <div className="example-summary" key={active.id}>
          <strong>{active.title}</strong>
          <span>{active.description}</span>
        </div>
        <div className="hero-actions">
          <a className="button primary" href={assetPath("examples/")}>
            More examples
          </a>
          <a className="button secondary" href="https://docs.rs/merkle-variants" target="_blank" rel="noreferrer">
            API docs
            <ArrowUpRightIcon className="link-icon" />
          </a>
        </div>
      </div>

      <div className="example-code-stage">
        <div className="example-orbit one" aria-hidden="true" />
        <div className="example-orbit two" aria-hidden="true" />
        <CodeWindow file={active.file} meta={active.meta} code={active.code} />
      </div>
    </section>
  );
}
