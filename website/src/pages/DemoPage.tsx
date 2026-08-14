import { useEffect, useState } from "react";
import { CodeWindow } from "../components/CodeWindow";
import { Footer } from "../components/Footer";
import { lightClientExample } from "../data/examples";
import { AppLayout } from "../layout/AppLayout";
import type { SiteData } from "../types/site";

type ProofSide = "Left" | "Right";

type ProofNode = {
  side: ProofSide;
  hash: Uint8Array;
};

type DemoResult = {
  root: string;
  leafHash: string;
  proof: Array<{ side: ProofSide; hash: string }>;
  verified: boolean;
  recomputedRoot: string;
  targetLeaf: string;
  leafIndex: number;
};

const proofSteps = [
  {
    label: "Server",
    title: "Build the full tree",
    copy: "A full node inserts transaction bytes and computes the trusted Merkle root.",
    detail: "3 leaves · SHA-256 · binary tree",
  },
  {
    label: "Witness",
    title: "Export only the proof",
    copy: "The server sends the root, the target transaction, and the sibling hashes on the proof path.",
    detail: "root + proof + tx bytes",
  },
  {
    label: "Drop",
    title: "Throw the tree away",
    copy: "The demo uses a Rust block scope so the tree is gone before verification starts.",
    detail: "zero tree database",
  },
  {
    label: "Client",
    title: "Verify statelessly",
    copy: "The client recomputes the path from the leaf and accepts only if it lands on the trusted root.",
    detail: "prints true",
  },
] as const;

const terminalLines = [
  "$ cargo run -p merkle-variants --example light_client",
  "server: built tree and exported root + proof",
  "client: tree dropped before verification",
  "Stateless verification: true",
] as const;

const defaultLeaves = [
  "tx:alice->bob:100",
  "tx:bob->carol:50",
  "tx:carol->dave:25",
  "tx:dave->erin:10",
] as const;

const encoder = new TextEncoder();

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const merged = new Uint8Array(length);
  let offset = 0;

  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  return merged;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const browserBytes = new Uint8Array(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", browserBytes.buffer as ArrayBuffer));
}

function nextPowerOfTwo(value: number): number {
  return 2 ** Math.ceil(Math.log2(Math.max(value, 1)));
}

async function hashLeaf(data: string): Promise<Uint8Array> {
  return sha256(concatBytes(new Uint8Array([0x00]), encoder.encode(data)));
}

async function hashNode(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(new Uint8Array([0x01]), left, right));
}

async function buildMerkleLayers(leaves: string[]): Promise<Uint8Array[][]> {
  const emptyLeaf = await hashLeaf("");
  const leafHashes = await Promise.all(leaves.map(hashLeaf));
  const paddedLeaves = [...leafHashes];

  while (paddedLeaves.length < nextPowerOfTwo(leaves.length)) {
    paddedLeaves.push(emptyLeaf);
  }

  const layers = [paddedLeaves];

  while (layers[layers.length - 1].length > 1) {
    const currentLayer = layers[layers.length - 1];
    const parentLayer: Uint8Array[] = [];

    for (let index = 0; index < currentLayer.length; index += 2) {
      parentLayer.push(await hashNode(currentLayer[index], currentLayer[index + 1]));
    }

    layers.push(parentLayer);
  }

  return layers;
}

function proofForIndex(layers: Uint8Array[][], leafIndex: number): ProofNode[] {
  const proof: ProofNode[] = [];
  let index = leafIndex;

  for (const layer of layers.slice(0, -1)) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    proof.push({
      side: index % 2 === 0 ? "Right" : "Left",
      hash: layer[siblingIndex],
    });
    index = Math.floor(index / 2);
  }

  return proof;
}

async function verifyProof(leaf: string, proof: ProofNode[]): Promise<Uint8Array> {
  let current = await hashLeaf(leaf);

  for (const node of proof) {
    current = node.side === "Left"
      ? await hashNode(node.hash, current)
      : await hashNode(current, node.hash);
  }

  return current;
}

async function runBrowserDemo(input: string, requestedLeafIndex: number): Promise<DemoResult> {
  const leaves = input
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  if (leaves.length === 0) {
    throw new Error("Add at least one transaction before running the demo.");
  }

  const leafIndex = Math.min(Math.max(requestedLeafIndex, 0), leaves.length - 1);
  const layers = await buildMerkleLayers(leaves);
  const root = layers[layers.length - 1][0];
  const proof = proofForIndex(layers, leafIndex);
  const recomputedRoot = await verifyProof(leaves[leafIndex], proof);

  return {
    root: bytesToHex(root),
    leafHash: bytesToHex(layers[0][leafIndex]),
    proof: proof.map((node) => ({ side: node.side, hash: bytesToHex(node.hash) })),
    verified: bytesToHex(root) === bytesToHex(recomputedRoot),
    recomputedRoot: bytesToHex(recomputedRoot),
    targetLeaf: leaves[leafIndex],
    leafIndex,
  };
}

export function DemoPage({ site }: { site: SiteData }) {
  const [activeStep, setActiveStep] = useState(0);
  const [leafInput, setLeafInput] = useState(defaultLeaves.join("\n"));
  const [leafIndex, setLeafIndex] = useState(0);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [error, setError] = useState("");
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    const id = window.setInterval(() => {
      setActiveStep((step) => (step + 1) % proofSteps.length);
    }, 1800);

    return () => window.clearInterval(id);
  }, []);

  async function runDemo() {
    setIsRunning(true);
    setError("");

    try {
      setResult(await runBrowserDemo(leafInput, leafIndex));
    } catch (caught) {
      setResult(null);
      setError(caught instanceof Error ? caught.message : "Could not run the browser demo.");
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <AppLayout page="demo" site={site}>
      <header className="page-hero demo-hero">
        <div>
          <span className="label">Light-client demo</span>
          <h1>Verify the proof after the tree is gone.</h1>
          <p>
            Run a real proof check in your browser. The page builds a small Merkle tree with
            SHA-256, extracts the proof for one transaction, throws away the tree data, and verifies
            using only the root, proof, and selected leaf.
          </p>
          <div className="demo-actions">
            <a className="button primary" href="#live-demo">
              Open live runner
            </a>
            <a className="button secondary" href={`${site.repositoryUrl}/issues/82`} target="_blank" rel="noreferrer">
              Issue #82
            </a>
          </div>
        </div>
        <div className="demo-orbital" aria-hidden="true">
          <span className="demo-root">Root</span>
          <span className="demo-leaf one">Tx</span>
          <span className="demo-leaf two">Tx</span>
          <span className="demo-leaf three">Tx</span>
          <span className="demo-proof-line a" />
          <span className="demo-proof-line b" />
          <span className="demo-client">Light client</span>
        </div>
      </header>

      <main className="demo-page section">
        <section className="demo-flow" aria-label="Stateless verification flow">
          <div className="section-head">
            <div>
              <span className="label">How it works</span>
              <h2>Full tree on the server. Tiny check on the client.</h2>
            </div>
            <p>
              Follow the highlighted card. The important part is the boundary between step 3 and
              step 4: verification happens after the original tree value has gone out of scope.
            </p>
          </div>

          <div className="demo-step-grid">
            {proofSteps.map((step, index) => (
              <button
                className={activeStep === index ? "demo-step active" : "demo-step"}
                key={step.title}
                type="button"
                onClick={() => setActiveStep(index)}
              >
                <span>{step.label}</span>
                <strong>{step.title}</strong>
                <p>{step.copy}</p>
                <small>{step.detail}</small>
              </button>
            ))}
          </div>
        </section>

        <section className="live-demo-panel" id="live-demo">
          <div className="section-head">
            <div>
              <span className="label">Run in browser</span>
              <h2>Build a proof, drop the tree, verify like a light client.</h2>
            </div>
            <p>
              Edit the transaction list, choose the leaf to prove, then run the verifier. This uses
              the same domain-separated Merkle rule as the SHA-256 adapter: `0x00 || leaf` and
              `0x01 || left || right`.
            </p>
          </div>

          <div className="live-demo-grid">
            <div className="live-demo-controls">
              <label htmlFor="demo-leaves">
                Transactions
                <span>One leaf per line. These are the only values used to build the tree.</span>
              </label>
              <textarea
                id="demo-leaves"
                value={leafInput}
                onChange={(event) => setLeafInput(event.target.value)}
                spellCheck={false}
              />

              <label htmlFor="demo-leaf-index">
                Leaf index to prove
                <span>Pick the transaction the light client should verify.</span>
              </label>
              <input
                id="demo-leaf-index"
                min={0}
                type="number"
                value={leafIndex}
                onChange={(event) => setLeafIndex(Number(event.target.value))}
              />

              <button className="button primary live-run-button" type="button" onClick={runDemo} disabled={isRunning}>
                {isRunning ? "Running..." : "Run stateless verification"}
              </button>

              {error && <p className="live-demo-error">{error}</p>}
            </div>

            <div className="live-demo-output" aria-live="polite">
              <div className={result?.verified ? "verification-badge valid" : "verification-badge"}>
                <span>{result ? (result.verified ? "Verified" : "Failed") : "Ready"}</span>
                <strong>{result ? String(result.verified) : "click run"}</strong>
              </div>

              <div className="live-proof-summary">
                <article>
                  <span>Target leaf</span>
                  <strong>{result ? `#${result.leafIndex}` : "#0"}</strong>
                  <code>{result?.targetLeaf ?? "tx:alice->bob:100"}</code>
                </article>
                <article>
                  <span>Trusted root</span>
                  <code>{result?.root.slice(0, 32) ?? "waiting for root"}...</code>
                </article>
                <article>
                  <span>Recomputed root</span>
                  <code>{result?.recomputedRoot.slice(0, 32) ?? "waiting for verifier"}...</code>
                </article>
                <article>
                  <span>Leaf hash</span>
                  <code>{result?.leafHash.slice(0, 32) ?? "waiting for leaf hash"}...</code>
                </article>
              </div>

              <div className="proof-path-list">
                <span className="label">Proof path</span>
                {(result?.proof ?? []).map((node, index) => (
                  <div className="proof-path-row" key={`${node.side}-${node.hash}`}>
                    <span>{index + 1}</span>
                    <strong>{node.side} sibling</strong>
                    <code>{node.hash.slice(0, 38)}...</code>
                  </div>
                ))}
                {!result && (
                  <div className="proof-path-row empty">
                    <span>0</span>
                    <strong>No proof yet</strong>
                    <code>Click run to generate sibling hashes.</code>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        <section className="demo-runner" id="run-it">
          <div className="demo-runner-copy">
            <span className="label">Rust reference</span>
            <h2>The checked-in example does the same thing locally.</h2>
            <p>
              The website runner proves the idea live. The Rust example is the library-native
              version for developers who want to run the same flow from the workspace.
            </p>
            <CodeWindow
              file="Terminal"
              meta="workspace root"
              code="cargo run -p merkle-variants --example light_client"
            />
            <div className="demo-terminal" aria-label="Expected command output">
              {terminalLines.map((line) => (
                <span className={line.endsWith("true") ? "success" : ""} key={line}>
                  {line}
                </span>
              ))}
            </div>
          </div>
          <CodeWindow file="merkle-variants/examples/light_client.rs" meta="stateless verifier" code={lightClientExample} />
        </section>
      </main>

      <Footer
        right={<a href={`${site.repositoryUrl}/tree/develop/merkle-variants/examples/light_client.rs`} target="_blank" rel="noreferrer">SOURCE ↗</a>}
      />
    </AppLayout>
  );
}
