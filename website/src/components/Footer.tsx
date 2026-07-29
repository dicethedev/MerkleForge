import type { ReactNode } from "react";
import { assetPath } from "../utils/paths";
import { BrandMark } from "./BrandMark";
import { ArrowUpRightIcon } from "./icons/ArrowUpRightIcon";

type FooterProps = {
  right: ReactNode;
};

export function Footer({ right }: FooterProps) {
  return (
    <footer className="site-footer">
      <div className="footer-main">
        <div className="footer-brand">
          <a className="brand" href={assetPath("index.html")}>
            <BrandMark />
            <span>MerkleForge</span>
          </a>
          <p>Typed Merkle trees, hash adapters, proofs, and benchmarks for Rust systems.</p>
        </div>
        <FooterColumn
          title="Learn"
          links={[
            ["Docs", assetPath("docs/")],
            ["Examples", assetPath("examples/")],
            ["Benchmarks", assetPath("benchmarks/")],
          ]}
        />
        <FooterColumn
          title="Crates"
          links={[
            ["merkle-core", "https://docs.rs/merkle-core"],
            ["merkleforge-hash", "https://docs.rs/merkleforge-hash"],
            ["merkle-variants", "https://docs.rs/merkle-variants"],
          ]}
        />
        <FooterColumn
          title="Project"
          links={[
            ["GitHub", "https://github.com/dicethedev/MerkleForge"],
            ["Releases", "https://github.com/dicethedev/MerkleForge/releases"],
            ["Issues", "https://github.com/dicethedev/MerkleForge/issues"],
          ]}
        />
      </div>
      <div className="footer-bottom">
        <span>© 2026-present Iwaju Labs and MerkleForge contributors.</span>
        <span>{right}</span>
      </div>
    </footer>
  );
}

function FooterColumn({ title, links }: { title: string; links: Array<[string, string]> }) {
  return (
    <div className="footer-column">
      <span>{title}</span>
      {links.map(([label, href]) => (
        <a
          href={href}
          key={label}
          target={href.startsWith("http") ? "_blank" : undefined}
          rel={href.startsWith("http") ? "noreferrer" : undefined}
        >
          {label}
          <ArrowUpRightIcon className="link-icon" />
        </a>
      ))}
    </div>
  );
}
