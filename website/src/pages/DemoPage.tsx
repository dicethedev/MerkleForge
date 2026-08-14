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
  leafCount: number;
};

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
    leafCount: leaves.length,
  };
}

export function DemoPage({ site }: { site: SiteData }) {
  const [leafInput, setLeafInput] = useState(defaultLeaves.join("\n"));
  const [leafIndex, setLeafIndex] = useState(0);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [error, setError] = useState("");
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    void runBrowserDemo(defaultLeaves.join("\n"), 0).then(setResult);
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
          <h1>Verify a transaction without downloading the tree.</h1>
          <p>
            Edit the transactions, pick one row, and run the proof check. The browser builds a
            Merkle root, creates a tiny proof, then verifies that one row using only the proof and
            root.
          </p>
          <div className="demo-actions">
            <a className="button primary" href="#live-demo">
              Try the live demo
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
        <section className="live-demo-panel" id="live-demo">
          <div className="section-head">
            <div>
              <span className="label">Live playground</span>
              <h2>Change the data. Run it. Watch the proof update.</h2>
            </div>
            <p>
              No setup. No local clone. This runs in your browser with Web Crypto SHA-256.
            </p>
          </div>

          <div className="live-demo-grid">
            <div className="live-demo-controls">
              <div className="playground-tabs" aria-label="Demo flow">
                <span>1 Edit</span>
                <span>2 Run</span>
                <span>3 Verify</span>
              </div>

              <label htmlFor="demo-leaves">
                Transactions to prove
                <span>Try changing names, amounts, or adding another line.</span>
              </label>
              <textarea
                id="demo-leaves"
                value={leafInput}
                onChange={(event) => setLeafInput(event.target.value)}
                spellCheck={false}
              />

              <label htmlFor="demo-leaf-index">
                Which row should the client check?
                <span>Rows start at 0, so the first transaction is row 0.</span>
              </label>
              <input
                id="demo-leaf-index"
                min={0}
                type="number"
                value={leafIndex}
                onChange={(event) => setLeafIndex(Number(event.target.value))}
              />

              <button
                className="button primary live-run-button"
                type="button"
                onClick={runDemo}
                disabled={isRunning}
              >
                {isRunning ? "Running..." : "Run proof"}
              </button>

              {error && <p className="live-demo-error">{error}</p>}
            </div>

            <div className="live-demo-output" aria-live="polite">
              <div className={result?.verified ? "verification-badge valid" : "verification-badge"}>
                <span>{result ? "Result" : "Ready"}</span>
                <strong>{result?.verified ? "Verified" : "Click run"}</strong>
              </div>

              <div className="proof-story">
                <div>
                  <span>Server</span>
                  <strong>{result ? `${result.leafCount} rows` : "waiting"}</strong>
                </div>
                <i />
                <div>
                  <span>Proof</span>
                  <strong>{result ? `${result.proof.length} hashes` : "waiting"}</strong>
                </div>
                <i />
                <div>
                  <span>Client</span>
                  <strong>{result?.verified ? "accepts" : "waiting"}</strong>
                </div>
              </div>

              <div className="live-proof-summary">
                <article>
                  <span>Checked row</span>
                  <strong>{result ? `#${result.leafIndex}` : "#0"}</strong>
                  <code>{result?.targetLeaf ?? "tx:alice->bob:100"}</code>
                </article>
                <article>
                  <span>Merkle root</span>
                  <code>{result?.root.slice(0, 32) ?? "waiting for root"}...</code>
                </article>
                <article>
                  <span>Client recomputed</span>
                  <code>{result?.recomputedRoot.slice(0, 32) ?? "waiting for verifier"}...</code>
                </article>
                <article>
                  <span>Leaf hash</span>
                  <code>{result?.leafHash.slice(0, 32) ?? "waiting for leaf hash"}...</code>
                </article>
              </div>

              <div className="proof-path-list">
                <span className="label">Tiny proof sent to the client</span>
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
                    <code>Click run to see the proof hashes.</code>
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
