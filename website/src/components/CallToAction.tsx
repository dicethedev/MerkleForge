import { assetPath } from "../utils/paths";
import { ArrowUpRightIcon } from "./icons/ArrowUpRightIcon";

export function CallToAction() {
  return (
    <section className="final-cta">
      <div className="cta-background" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
        <span />
      </div>
      <div className="cta-content">
        <span className="label">Ready to verify?</span>
        <h2>Build proof-backed Rust systems with MerkleForge.</h2>
        <p>
          Install the crates, try the examples, then compare real benchmark reports before choosing
          the tree shape for your project.
        </p>
        <div className="cta-actions">
          <a className="button primary light" href={assetPath("docs/")}>
            Get started
          </a>
          <a className="button secondary glass" href={assetPath("benchmarks/")}>
            View benchmarks
            <ArrowUpRightIcon className="link-icon" />
          </a>
        </div>
      </div>
    </section>
  );
}
