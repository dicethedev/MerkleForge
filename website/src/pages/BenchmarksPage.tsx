import { useMemo, useState } from "react";
import { BenchmarkCard } from "../components/BenchmarkCard";
import { CodeWindow } from "../components/CodeWindow";
import { Footer } from "../components/Footer";
import { Section } from "../components/Section";
import { SignalCell } from "../components/SignalCell";
import { Stat } from "../components/Stat";
import { useJson } from "../hooks/useJson";
import { AppLayout } from "../layout/AppLayout";
import type { BenchmarkData, BenchmarkSample, SiteData } from "../types/site";
import { formatDuration, operationLabel } from "../utils/format";
import { assetPath } from "../utils/paths";

type BenchmarksPageProps = {
  site: SiteData;
  benchmarks: BenchmarkData;
};

const comparisonRows = [
  {
    metric: "10K leaf construction",
    plain: "Build a binary Merkle tree from 10,000 leaves.",
    unit: "ms",
    values: {
      merkleforge: 16.93,
      rsMerkle: 2.7,
      merkleLight: 2.19,
    },
  },
  {
    metric: "Proof size",
    plain: "Bytes needed to send one inclusion proof from a 10K-leaf tree.",
    unit: "bytes",
    values: {
      merkleforge: 469,
      rsMerkle: 448,
      merkleLight: 512,
    },
  },
  {
    metric: "Proof verification",
    plain: "Time to check one inclusion proof against a trusted root.",
    unit: "µs",
    values: {
      merkleforge: 1.87,
      rsMerkle: 7.16,
      merkleLight: 1.88,
    },
  },
];

function comparisonWidth(value: number, values: Record<string, number>) {
  const slowest = Math.max(...Object.values(values));
  return `${Math.max(8, (value / slowest) * 100).toFixed(1)}%`;
}

export function BenchmarksPage({ site, benchmarks }: BenchmarksPageProps) {
  const data = useJson<BenchmarkData>("benchmark-data.json", benchmarks);
  const [filter, setFilter] = useState("all");
  const [showBenchmarkHelp, setShowBenchmarkHelp] = useState(false);
  const operationKeys = useMemo(
    () => [...new Set(data.benchmarks.map(item => item.operation_key))],
    [data],
  );
  const visible = useMemo(
    () =>
      data.benchmarks
        .filter(item => filter === "all" || item.operation_key === filter)
        .sort(
          (a, b) =>
            a.operation.localeCompare(b.operation) ||
            a.size_value - b.size_value ||
            a.mean_ns - b.mean_ns,
        ),
    [data, filter],
  );

  const fastest = data.benchmarks.reduce<BenchmarkSample | null>(
    (best, item) => (!best || item.mean_ns < best.mean_ns ? item : best),
    null,
  );
  const generatedAt = new Date(data.generatedAt).toLocaleString();

  return (
    <AppLayout page="benchmarks" site={site}>
      <header className="page-hero benchmark-hero">
        <div>
          <h1>
            See how MerkleForge performs before you use it.
          </h1>
          <p>
            This page turns Criterion benchmark output into a simple dashboard. Use it to compare
            operations, hash functions, and dataset sizes. Developers can still open the raw
            Criterion reports for the full statistical detail.
          </p>
        </div>
        <div className="benchmark-hero-art" aria-hidden="true">
          <span />
          <span />
          <span />
          <span />
          <span />
        </div>
      </header>
      <section className="benchmark-guide">
        <article>
          <span>01</span>
          <strong>Lower time is better</strong>
          <p>Each row shows the average time for one measured operation.</p>
        </article>
        <article>
          <span>02</span>
          <strong>Compare similar rows</strong>
          <p>Compare rows with the same operation and leaf count for the clearest signal.</p>
        </article>
        <article>
          <span>03</span>
          <strong>Hardware matters</strong>
          <p>Use absolute numbers as a guide. Re-run locally for your machine.</p>
        </article>
      </section>
      <section className="signal-strip benchmark-strip">
        <SignalCell label="Run locally" value={<code>cargo bench --bench binary_tree</code>} />
        <SignalCell label="Tooling" value="Criterion.rs" />
        <SignalCell label="Confidence range" value="95%" />
        <SignalCell label="Generated" value={generatedAt} />
      </section>
      <main>
        <Section
          label=""
          title="Quick read before the raw numbers."
          copy="Start here if you only want the headline. These cards show how many benchmark cases were found, how many workflows were measured, and the fastest recorded sample."
        >
          <div className="stats">
            <Stat label="Benchmark cases" value={String(data.benchmarks.length)} note="completed measurements" />
            <Stat label="Workflows" value={String(operationKeys.length)} note="operations you can filter" />
            <Stat
              label="Hash functions"
              value={String(new Set(data.benchmarks.map(item => item.algorithm)).size)}
              note="algorithms compared"
            />
            <Stat
              label="Fastest result"
              value={fastest ? formatDuration(fastest.mean_ns) : "n/a"}
              note={fastest?.algorithm ?? "awaiting data"}
            />
          </div>
        </Section>

        <Section
          label="Reports"
          title="Readable dashboard. Raw reports when you need them."
          copy="The cards below are for quick decisions. The raw Criterion report is there for reviewers who want plots, confidence intervals, and outlier analysis."
        >
          <div className="report-grid">
            <article className="report-card">
              <span className="label">Raw evidence</span>
              <h3>Open the Criterion report</h3>
              <p>Use this when you want the full statistical report behind the dashboard numbers.</p>
              <a className="button secondary" href={assetPath("reports/criterion/binary_tree/report/index.html")}>
                Open raw report ↗
              </a>
            </article>
            <article className="report-card">
              <span className="label">Run it yourself</span>
              <h3>Compare on your hardware</h3>
              <p>
                Benchmark numbers change by machine. Run the suite that matches the tree you care
                about, then compare the results with this dashboard.
              </p>
              <div className="bench-command-stack">
                <CodeWindow file="Binary tree" meta="ordered leaves" code="cargo bench --bench binary_tree" />
                <CodeWindow file="Sparse tree" meta="256-bit state" code="cargo bench --bench sparse_tree" />
                <CodeWindow file="Patricia trie" meta="Ethereum-style" code="cargo bench --bench patricia_trie" />
              </div>
            </article>
          </div>
        </Section>

        <Section
          label="Comparison"
          title="MerkleForge beside the Rust crates it is measured against."
          copy="Objective 3 compares MerkleForge with rs-merkle and merkle_light using the same 10,000-leaf binary-tree workload. Lower numbers are better in every row."
        >
          <div className="comparison-panel">
            <div className="comparison-summary">
              <article>
                <span>Best MerkleForge result</span>
                <strong>3.1x faster proof verification than rs-merkle</strong>
                <p>
                  MerkleForge verifies a 10K-tree inclusion proof in 1.87 µs, while rs-merkle
                  measures 7.16 µs on the same local run.
                </p>
              </article>
              <article>
                <span>Smallest proof</span>
                <strong>rs-merkle by 21 bytes</strong>
                <p>
                  MerkleForge proofs are close to rs-merkle and smaller than merkle_light in this
                  benchmark snapshot.
                </p>
              </article>
            </div>
            <div className="comparison-table" role="table" aria-label="Comparative benchmark results">
              <div className="comparison-row comparison-head" role="row">
                <span role="columnheader">Metric</span>
                <span role="columnheader">MerkleForge</span>
                <span role="columnheader">rs-merkle</span>
                <span role="columnheader">merkle_light</span>
              </div>
              {comparisonRows.map(row => (
                <div className="comparison-row" role="row" key={row.metric}>
                  <div className="comparison-metric" role="cell">
                    <strong>{row.metric}</strong>
                    <p>{row.plain}</p>
                  </div>
                  {[
                    ["merkleforge", "MerkleForge"],
                    ["rsMerkle", "rs-merkle"],
                    ["merkleLight", "merkle_light"],
                  ].map(([key, label]) => {
                    const value = row.values[key as keyof typeof row.values];
                    const best = value === Math.min(...Object.values(row.values));
                    return (
                      <div className={`comparison-value ${best ? "best" : ""}`} role="cell" key={key}>
                        <span className="mobile-label">{label}</span>
                        <strong>
                          {value.toLocaleString(undefined, { maximumFractionDigits: 2 })} {row.unit}
                        </strong>
                        <div className="comparison-track">
                          <span style={{ width: comparisonWidth(value, row.values) }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
            <p className="comparison-note">
              Measured locally with <code>cargo bench --bench comparison</code>. Hardware, CPU
              governor, and dependency versions can move the absolute values, so use the trend and
              rerun locally when exact timing matters.
            </p>
            <div className="comparison-explainer" aria-label="What the comparison metrics mean">
              <article>
                <strong>Construction time</strong>
                <p>
                  How long it takes to build a binary Merkle tree from 10,000 leaves. Lower means the
                  tree is built faster.
                </p>
              </article>
              <article>
                <strong>Proof size</strong>
                <p>
                  How many bytes one inclusion proof takes when serialized or sent over a network.
                  Lower means cheaper storage and bandwidth.
                </p>
              </article>
              <article>
                <strong>Proof verification</strong>
                <p>
                  How long it takes to check one proof against a trusted root. Lower means faster
                  light-client or verifier checks.
                </p>
              </article>
              <article className="comparison-takeaway">
                <strong>Current takeaway</strong>
                <p>
                  MerkleForge is strongest at proof verification and competitive on proof size, but
                  slower at 10K tree construction in this snapshot.
                </p>
              </article>
            </div>
          </div>
        </Section>

        <section className="section" id="results">
          <div className="section-head">
            <div>
              <span className="label">Results</span>
              <h2>Read each result in three steps.</h2>
            </div>
            <p className="section-copy">
              First check what ran, then compare the average time, then confirm the data size. Lower
              time is better. Open the raw report when you want deeper statistics.
            </p>
          </div>
          <div className="results-reader">
            <article>
              <span>What ran</span>
              <p>The operation, tree variant, and hash algorithm used for this row.</p>
            </article>
            <article>
              <span>Average time</span>
              <p>The mean time Criterion measured. The small range below it shows uncertainty.</p>
            </article>
            <article>
              <span>Data size</span>
              <p>The number of leaves or updates used for that benchmark case.</p>
            </article>
          </div>
          <div className="results-toolbar">
            <div className="controls">
              {[["all", "All samples"], ...operationKeys.map(key => [key, operationLabel(key)])].map(([key, label]) => (
                <button
                  className={`filter ${filter === key ? "active" : ""}`}
                  data-filter={key}
                  key={key}
                  onClick={() => setFilter(key)}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="results-help-actions">
              <span className="results-key">Average time / likely 95% range</span>
              <button className="button secondary help-button" type="button" onClick={() => setShowBenchmarkHelp(true)}>
                How to read this
              </button>
            </div>
          </div>
          <div className="benchmark-grid">
            {visible.map((item, index) => (
              <BenchmarkCard item={item} index={index} samples={data.benchmarks} key={item.id} />
            ))}
          </div>
          <div className="empty" style={{ display: visible.length ? "none" : "block" }}>
            No completed benchmark samples were found.
          </div>
        </section>
      </main>
      {showBenchmarkHelp ? (
        <div className="modal-backdrop" role="presentation" onClick={() => setShowBenchmarkHelp(false)}>
          <section
            className="benchmark-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="benchmark-help-title"
            onClick={event => event.stopPropagation()}
          >
            <div className="modal-head">
              <span className="label">Benchmark guide</span>
              <button className="copy-code" type="button" onClick={() => setShowBenchmarkHelp(false)} aria-label="Close benchmark guide">
                X
              </button>
            </div>
            <h2 id="benchmark-help-title">How to read benchmark results</h2>
            <p>
              These numbers are a performance guide, not a permanent promise. Use them to compare
              similar rows, then run the same benchmark on your own machine before making a final
              production decision.
            </p>
            <div className="modal-grid">
              <article>
                <strong>Time</strong>
                <span>
                  The average duration for one benchmarked operation. Lower is better. For example,
                  934.41 us means 934.41 microseconds, or about 0.000934 seconds.
                </span>
              </article>
              <article>
                <strong>Likely range</strong>
                <span>The 95% confidence interval from Criterion. A tight range means a stable run.</span>
              </article>
              <article>
                <strong>Data size</strong>
                <span>The number of leaves, keys, or updates used in that benchmark case.</span>
              </article>
              <article>
                <strong>Speed</strong>
                <span>Throughput when Criterion reports element counts, shown as leaves per second.</span>
              </article>
              <article>
                <strong>Latency only</strong>
                <span>The benchmark measures time, but there is no useful elements-per-second value.</span>
              </article>
              <article>
                <strong>Raw report</strong>
                <span>Criterion's detailed page with plots, distributions, outliers, and statistics.</span>
              </article>
            </div>
          </section>
        </div>
      ) : null}
      <Footer right={<>COMMIT {data.commit} · HARDWARE AFFECTS RESULTS</>} />
    </AppLayout>
  );
}
