import { useEffect, useState } from "react";
import { CodeWindow } from "../components/CodeWindow";
import { Footer } from "../components/Footer";
import { lightClientExample } from "../data/examples";
import { AppLayout } from "../layout/AppLayout";
import type { SiteData } from "../types/site";

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

export function DemoPage({ site }: { site: SiteData }) {
  const [activeStep, setActiveStep] = useState(0);

  useEffect(() => {
    const id = window.setInterval(() => {
      setActiveStep((step) => (step + 1) % proofSteps.length);
    }, 1800);

    return () => window.clearInterval(id);
  }, []);

  return (
    <AppLayout page="demo" site={site}>
      <header className="page-hero demo-hero">
        <div>
          <span className="label">Light-client demo</span>
          <h1>Verify the proof after the tree is gone.</h1>
          <p>
            This page shows the MerkleForge stateless verification flow in the smallest useful
            shape: a server builds the tree, exports a proof, drops the tree, and a client verifies
            with only the root hash, proof, and target leaf bytes.
          </p>
          <div className="demo-actions">
            <a className="button primary" href="#run-it">
              Run the example
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

        <section className="demo-runner" id="run-it">
          <div className="demo-runner-copy">
            <span className="label">Runnable evidence</span>
            <h2>Copy the example, or run the checked-in binary.</h2>
            <p>
              The example lives in `merkle-variants/examples/light_client.rs`. It prints `true`
              only after the tree has been dropped, which demonstrates the light-client proof
              contract end to end.
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
