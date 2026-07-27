export function SponsorSection() {
  return (
    <section className="sponsor-section">
      <div className="sponsor-copy">
        <span className="label">Open source</span>
        <h2>Free to use. Built in the open.</h2>
        <p>
          MerkleForge is MIT licensed and will always be free and open source. Sponsor support is
          coming soon to help fund docs, benchmarks, audits, and long-term maintenance.
        </p>
        <button className="button secondary sponsor-button" type="button" disabled>
          Become a sponsor · coming soon
        </button>
      </div>
      <div className="sponsor-visual" aria-hidden="true">
        <div className="open-source-mark">
          <span className="open-ring" />
          <span className="open-node top" />
          <span className="open-node left" />
          <span className="open-node right" />
          <span className="open-line one" />
          <span className="open-line two" />
          <span className="open-core" />
        </div>
        <div className="open-source-text">
          <span>Free forever</span>
          <strong>Open source</strong>
          <small>Built for transparent, verifiable systems.</small>
        </div>
      </div>
    </section>
  );
}
