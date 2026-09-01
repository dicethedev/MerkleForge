import { CallToAction } from "../components/CallToAction";
import { CommandPanel } from "../components/CommandPanel";
import { CrateCard } from "../components/CrateCard";
import { ExampleShowcase } from "../components/ExampleShowcase";
import { FeatureCard } from "../components/FeatureCard";
import { Footer } from "../components/Footer";
import { MerklePrism } from "../components/MerklePrism";
import { Section } from "../components/Section";
import { SponsorSection } from "../components/SponsorSection";
import { AppLayout } from "../layout/AppLayout";
import type { SiteData } from "../types/site";
import { assetPath } from "../utils/paths";

export function HomePage({ site }: { site: SiteData }) {
  return (
    <AppLayout page="home" site={site}>
      <main>
        <header className="hero vite-hero">
          <div className="hero-copy hero-copy-centered">
            <h1 className="hero-title">
              The Merkle Framework
              <span>for verifiable systems.</span>
            </h1>
            <p className="lede hero-lede">
              Build binary trees, sparse state trees, and Ethereum-compatible Patricia tries from one
              typed Rust API. Generate proofs, verify roots, and compare performance with real
              Criterion reports.
            </p>
            <div className="hero-actions">
              <a className="button primary" href={assetPath("docs/")}>
                Get started
              </a>
              <a className="button secondary" href={assetPath("examples/")}>
                View examples
              </a>
            </div>
            <CommandPanel crateVersion={site.crateVersion} />
          </div>
          <MerklePrism />
        </header>

        <Section
          label="What you get"
          title="Build, prove, and verify data with one Rust framework."
          copy="MerkleForge gives you the common pieces needed for authenticated data: hash adapters, tree variants, proofs, examples, and benchmark reports."
        >
          <div className="feature-orbit-grid">
            <FeatureCard number="Hash functions" title="Choose a hash" link="docs/" linkText="Read docs" visual="hash">
              Use SHA-256, Keccak-256, or BLAKE3 without changing your tree code.
            </FeatureCard>
            <FeatureCard number="Proof" title="Prove a value exists" link="examples/" linkText="See examples" visual="proof">
              Send a small proof so another app can verify data without downloading everything.
            </FeatureCard>
            <FeatureCard number="Measure" title="Compare performance" link="benchmarks/" linkText="View benchmarks" visual="chart">
              Check measured speed for tree operations and hash algorithms before choosing a setup.
            </FeatureCard>
          </div>
        </Section>

        <section className="variant-showcase">
          <div className="variant-intro">
            <span className="label">Variants</span>
            <h2>Pick the tree that fits your data.</h2>
            <p>
              Start with a simple binary tree, scale to sparse state, or use an Ethereum-style
              Patricia trie. The API stays familiar across all three.
            </p>
          </div>
          <div className="variant-grid">
            <article className="variant-card binary-card">
              <h3>Binary Merkle Tree</h3>
              <p>Best for ordered lists like blocks, files, logs, or transaction batches.</p>
              <span className="variant-note">Fast roots and compact inclusion proofs.</span>
              <div className="mini-tree" aria-hidden="true">
                <span />
                <span />
                <span />
                <span />
                <span />
                <span />
                <span />
              </div>
            </article>
            <article className="variant-card sparse-card">
              <h3>Sparse Merkle Tree</h3>
              <p>Best for huge key spaces where most entries are empty.</p>
              <span className="variant-note">Great for state maps, rollups, and absence proofs.</span>
              <div className="sparse-map" aria-hidden="true">
                {Array.from({ length: 24 }, (_, index) => (
                  <span className={index % 7 === 0 ? "hot" : ""} key={index} />
                ))}
              </div>
            </article>
            <article className="variant-card patricia-card">
              <h3>Merkle Patricia Trie</h3>
              <p>Best for Ethereum-compatible state, receipts, and account storage.</p>
              <span className="variant-note">Uses nibble paths, RLP nodes, and witness proofs.</span>
              <div className="nibble-radix" aria-hidden="true">
                {Array.from({ length: 16 }, (_, index) => (
                  <span key={index}>{index.toString(16)}</span>
                ))}
              </div>
            </article>
          </div>
        </section>

        <Section
          label="Workspace"
          title="Install only the piece you need."
          copy="MerkleForge is split into small crates so your app can stay lean. Start with traits, add hash adapters, then bring in tree implementations when you need them."
        >
          <div className="crate-grid">
            <CrateCard badge="Shared API" name="merkle-core" docs="https://docs.rs/merkle-core" visual="core">
              The common language: tree traits, proof types, metadata, serialization, and errors.
            </CrateCard>
            <CrateCard badge="Hashing" name="merkleforge-hash" docs="https://docs.rs/merkleforge-hash" visual="hash">
              Ready-made SHA-256, Keccak-256, and BLAKE3 adapters for the tree crates.
            </CrateCard>
            <CrateCard badge="Tree types" name="merkle-variants" docs="https://docs.rs/merkle-variants" visual="trees">
              Use binary trees, sparse trees, and Ethereum-compatible Patricia tries out of the box.
            </CrateCard>
          </div>
        </Section>

        <ExampleShowcase />
        <SponsorSection />
        <CallToAction />
      </main>
      <Footer right="MIT OR APACHE-2.0" />
    </AppLayout>
  );
}
