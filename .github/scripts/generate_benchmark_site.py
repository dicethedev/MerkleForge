#!/usr/bin/env python3
"""Generate the MerkleForge benchmark dashboard from Criterion JSON output."""

from __future__ import annotations

import argparse
import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def collect_benchmarks(criterion_dir: Path) -> list[dict[str, Any]]:
    benchmarks: list[dict[str, Any]] = []

    for benchmark_path in sorted(criterion_dir.glob("**/new/benchmark.json")):
        estimates_path = benchmark_path.with_name("estimates.json")
        if not estimates_path.exists():
            continue

        benchmark = load_json(benchmark_path)
        estimates = load_json(estimates_path)
        function_id = str(benchmark.get("function_id", "benchmark"))
        operation, separator, algorithm = function_id.partition("/")
        mean = estimates["mean"]
        confidence = mean["confidence_interval"]
        throughput = benchmark.get("throughput") or {}
        elements = throughput.get("Elements")
        mean_ns = float(mean["point_estimate"])

        benchmarks.append(
            {
                "id": str(benchmark["full_id"]),
                "operation": operation.replace("_", " ").title(),
                "operation_key": operation,
                "algorithm": algorithm if separator else "Default",
                "size": str(benchmark.get("value_str", "n/a")),
                "size_value": parse_size(benchmark.get("value_str")),
                "mean_ns": mean_ns,
                "lower_ns": float(confidence["lower_bound"]),
                "upper_ns": float(confidence["upper_bound"]),
                "elements_per_second": (
                    float(elements) * 1_000_000_000 / mean_ns
                    if elements is not None and mean_ns > 0
                    else None
                ),
                "report": (
                    "benchmarks/"
                    + str(benchmark["directory_name"])
                    + "/report/index.html"
                ),
            }
        )

    return benchmarks


def parse_size(value: Any) -> float:
    try:
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return 0


def render_site(
    benchmarks: list[dict[str, Any]],
    output_path: Path,
    repository_url: str,
    commit_sha: str,
) -> None:
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    payload = json.dumps(
        {
            "benchmarks": benchmarks,
            "generatedAt": generated_at,
            "commit": commit_sha[:7] if commit_sha else "local",
        },
        separators=(",", ":"),
    ).replace("</", "<\\/")

    page = PAGE_TEMPLATE.replace("__DATA__", payload)
    page = page.replace("__REPOSITORY_URL__", html.escape(repository_url, quote=True))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(page)


PAGE_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="MerkleForge performance benchmark observatory.">
  <title>MerkleForge / Performance Observatory</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --void: #070a0e;
      --steel: #0d1219;
      --panel: #111821;
      --panel-hot: #17212c;
      --line: #25313d;
      --line-bright: #354657;
      --text: #eef4f8;
      --muted: #81909f;
      --cyan: #37d6e6;
      --cyan-soft: rgba(55, 214, 230, .12);
      --ember: #ff9b42;
      --lime: #adff5c;
      --display: "Space Grotesk", sans-serif;
      --mono: "IBM Plex Mono", monospace;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      color: var(--text);
      background:
        linear-gradient(rgba(37, 49, 61, .18) 1px, transparent 1px),
        linear-gradient(90deg, rgba(37, 49, 61, .18) 1px, transparent 1px),
        var(--void);
      background-size: 48px 48px;
      font-family: var(--display);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background: radial-gradient(circle at 72% 8%, rgba(55, 214, 230, .09), transparent 31%);
    }
    a { color: inherit; }
    button { font: inherit; }
    .shell { width: min(1240px, calc(100% - 48px)); margin: 0 auto; }
    .mono, .label { font-family: var(--mono); }
    .label {
      color: var(--muted);
      font-size: 10px;
      letter-spacing: .13em;
      text-transform: uppercase;
    }
    .nav {
      display: flex;
      align-items: center;
      min-height: 72px;
      border-bottom: 1px solid var(--line);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-right: auto;
      font-weight: 700;
      text-decoration: none;
      letter-spacing: -.03em;
    }
    .brand-mark { width: 29px; height: 29px; color: var(--cyan); }
    .brand small {
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 8px;
      font-weight: 400;
      letter-spacing: .12em;
      text-transform: uppercase;
    }
    .nav-links { display: flex; align-items: center; gap: 28px; }
    .nav-link {
      color: var(--muted);
      font-family: var(--mono);
      font-size: 10px;
      text-decoration: none;
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    .nav-link:hover { color: var(--cyan); }
    .source-link {
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 0 13px;
      border: 1px solid var(--line-bright);
      color: var(--text);
      font-family: var(--mono);
      font-size: 10px;
      text-decoration: none;
      text-transform: uppercase;
    }
    .source-link:hover { border-color: var(--cyan); color: var(--cyan); }
    .hero {
      position: relative;
      display: grid;
      grid-template-columns: .9fr 1.1fr;
      min-height: 610px;
      border-bottom: 1px solid var(--line);
    }
    .hero-copy {
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: 70px 56px 70px 0;
      border-right: 1px solid var(--line);
    }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 9px;
      width: fit-content;
      margin-bottom: 30px;
      color: var(--lime);
      font-family: var(--mono);
      font-size: 10px;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    .status::before {
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--lime);
      box-shadow: 0 0 14px var(--lime);
    }
    h1 {
      margin: 0;
      font-size: clamp(48px, 6.5vw, 88px);
      line-height: .91;
      letter-spacing: -.075em;
    }
    h1 span {
      display: block;
      color: transparent;
      -webkit-text-stroke: 1px var(--cyan);
    }
    .lede {
      max-width: 540px;
      margin: 30px 0 0;
      color: var(--muted);
      font-size: 15px;
    }
    .hero-actions { display: flex; gap: 12px; margin-top: 32px; }
    .primary, .secondary {
      display: inline-flex;
      align-items: center;
      min-height: 42px;
      padding: 0 16px;
      font-family: var(--mono);
      font-size: 10px;
      text-decoration: none;
      text-transform: uppercase;
      letter-spacing: .06em;
    }
    .primary { color: #041014; background: var(--cyan); }
    .secondary { border: 1px solid var(--line-bright); color: var(--muted); }
    .tree-stage {
      position: relative;
      display: grid;
      place-items: center;
      min-width: 0;
      overflow: hidden;
      background: linear-gradient(135deg, rgba(17, 24, 33, .2), rgba(55, 214, 230, .035));
    }
    .tree-stage::after {
      content: "HASH TOPOLOGY / BINARY";
      position: absolute;
      right: 22px;
      bottom: 18px;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 8px;
      letter-spacing: .16em;
    }
    .tree-visual { width: min(92%, 650px); height: auto; overflow: visible; }
    .tree-line { stroke: #293947; stroke-width: 1.5; }
    .tree-line.hot { stroke: var(--cyan); filter: drop-shadow(0 0 4px rgba(55, 214, 230, .7)); }
    .node { fill: var(--panel); stroke: #435568; stroke-width: 1.5; }
    .node.root { fill: var(--cyan); stroke: #b9f8ff; }
    .node.leaf { fill: var(--void); stroke: var(--ember); }
    .node-label { fill: var(--muted); font-family: var(--mono); font-size: 9px; }
    .root-label { fill: var(--cyan); font-family: var(--mono); font-size: 9px; letter-spacing: .1em; }
    .pulse { animation: pulse 2.6s ease-in-out infinite; transform-origin: center; }
    @keyframes pulse { 50% { opacity: .55; } }
    .run-strip {
      display: grid;
      grid-template-columns: 1.5fr repeat(3, 1fr);
      border-bottom: 1px solid var(--line);
      background: var(--steel);
    }
    .run-cell { min-height: 102px; padding: 22px 24px; border-right: 1px solid var(--line); }
    .run-cell:last-child { border-right: 0; }
    .command { margin-top: 13px; color: var(--cyan); font-family: var(--mono); font-size: 12px; }
    .run-value { display: block; margin-top: 10px; font-family: var(--mono); font-size: 17px; }
    .section { padding: 76px 0; border-bottom: 1px solid var(--line); }
    .section-head {
      display: grid;
      grid-template-columns: 1fr 1fr;
      align-items: end;
      gap: 48px;
      margin-bottom: 30px;
    }
    h2 { max-width: 560px; margin: 8px 0 0; font-size: 38px; line-height: 1.05; letter-spacing: -.05em; }
    .section-copy { max-width: 520px; margin: 0; color: var(--muted); font-size: 13px; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); border: 1px solid var(--line); }
    .stat-card { min-height: 154px; padding: 23px; border-right: 1px solid var(--line); background: rgba(13, 18, 25, .78); }
    .stat-card:last-child { border-right: 0; }
    .stat-value { display: block; margin: 30px 0 4px; color: var(--text); font-family: var(--mono); font-size: 27px; }
    .stat-card:first-child .stat-value { color: var(--cyan); }
    .stat-note { color: var(--muted); font-size: 11px; }
    .results-toolbar {
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: center;
      margin-bottom: 12px;
    }
    .controls { display: flex; flex-wrap: wrap; gap: 7px; }
    .filter {
      min-height: 34px;
      padding: 0 12px;
      border: 1px solid var(--line);
      color: var(--muted);
      background: var(--steel);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 9px;
      letter-spacing: .06em;
      text-transform: uppercase;
    }
    .filter.active, .filter:hover { border-color: var(--cyan); color: var(--cyan); background: var(--cyan-soft); }
    .results-key { color: var(--muted); font-family: var(--mono); font-size: 9px; text-transform: uppercase; }
    .benchmark-grid { border-top: 1px solid var(--line); }
    .benchmark-card {
      display: grid;
      grid-template-columns: 34px minmax(170px, .8fr) minmax(210px, 1.2fr) minmax(150px, .7fr) 120px;
      gap: 20px;
      align-items: center;
      min-height: 116px;
      padding: 18px 20px;
      border: 1px solid var(--line);
      border-top: 0;
      background: rgba(13, 18, 25, .75);
      transition: background .18s, border-color .18s;
    }
    .benchmark-card:hover { position: relative; border-color: var(--line-bright); background: var(--panel); }
    .index { color: #4e6070; font-family: var(--mono); font-size: 10px; }
    .operation { margin: 5px 0 0; font-size: 17px; letter-spacing: -.025em; }
    .algorithm { display: block; margin-top: 5px; color: var(--ember); font-family: var(--mono); font-size: 10px; }
    .measurement { min-width: 0; }
    .duration { font-family: var(--mono); font-size: 21px; font-weight: 500; }
    .track { height: 4px; margin: 12px 0 7px; overflow: hidden; background: #1b2631; }
    .bar { height: 100%; width: var(--width); background: linear-gradient(90deg, var(--cyan), #7cf0c6); box-shadow: 0 0 10px rgba(55, 214, 230, .35); }
    .confidence { overflow: hidden; color: var(--muted); font-family: var(--mono); font-size: 8px; text-overflow: ellipsis; white-space: nowrap; }
    .size { font-family: var(--mono); font-size: 13px; }
    .size small, .throughput small { display: block; margin-bottom: 5px; color: var(--muted); font-size: 8px; letter-spacing: .08em; text-transform: uppercase; }
    .throughput { color: var(--lime); font-family: var(--mono); font-size: 10px; }
    .report-link {
      display: inline-flex;
      justify-content: center;
      align-items: center;
      min-height: 34px;
      border: 1px solid var(--line-bright);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 9px;
      text-decoration: none;
      text-transform: uppercase;
    }
    .report-link:hover { border-color: var(--cyan); color: var(--cyan); }
    .empty { display: none; padding: 50px 0; color: var(--muted); text-align: center; }
    footer { display: flex; justify-content: space-between; gap: 20px; padding: 32px 0 46px; color: var(--muted); font-family: var(--mono); font-size: 9px; }
    @media (max-width: 920px) {
      .hero { grid-template-columns: 1fr; }
      .hero-copy { min-height: 520px; padding-right: 0; border-right: 0; border-bottom: 1px solid var(--line); }
      .tree-stage { min-height: 470px; }
      .run-strip { grid-template-columns: 1fr 1fr; }
      .run-cell:nth-child(2) { border-right: 0; }
      .run-cell:nth-child(-n+2) { border-bottom: 1px solid var(--line); }
      .stats { grid-template-columns: 1fr 1fr; }
      .stat-card:nth-child(2) { border-right: 0; }
      .stat-card:nth-child(-n+2) { border-bottom: 1px solid var(--line); }
      .benchmark-card { grid-template-columns: 28px 1fr 1.2fr; }
      .benchmark-card .size, .benchmark-card .throughput { display: none; }
    }
    @media (max-width: 620px) {
      .shell { width: min(100% - 24px, 1240px); }
      .nav { min-height: 62px; }
      .nav-link { display: none; }
      .hero-copy { min-height: 500px; padding: 56px 0; }
      h1 { font-size: 52px; }
      .tree-stage { min-height: 330px; }
      .run-strip { grid-template-columns: 1fr; }
      .run-cell { min-height: 82px; border-right: 0; border-bottom: 1px solid var(--line); }
      .run-cell:last-child { border-bottom: 0; }
      .section { padding: 58px 0; }
      .section-head { grid-template-columns: 1fr; gap: 16px; }
      h2 { font-size: 31px; }
      .stats { grid-template-columns: 1fr 1fr; }
      .stat-card { min-height: 130px; padding: 17px; }
      .stat-value { margin-top: 22px; font-size: 21px; }
      .results-toolbar { display: block; }
      .results-key { display: block; margin-top: 12px; }
      .benchmark-card { grid-template-columns: 24px 1fr; gap: 12px; padding: 18px 12px; }
      .benchmark-card .measurement { grid-column: 2; }
      .benchmark-card .report-link { grid-column: 2; width: 140px; }
      footer { flex-direction: column; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <nav class="nav">
      <a class="brand" href="#">
        <svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true">
          <path d="M16 3 5 9.5v13L16 29l11-6.5v-13L16 3Z" fill="none" stroke="currentColor"/>
          <path d="m5 9.5 11 6.4 11-6.4M16 15.9V29M10.5 12.7 16 9.5l5.5 3.2" fill="none" stroke="currentColor"/>
        </svg>
        <span>MerkleForge<small>Performance observatory</small></span>
      </a>
      <div class="nav-links">
        <a class="nav-link" href="#results">Dataset</a>
        <a class="nav-link" href="benchmarks/binary_tree/report/index.html">Criterion</a>
        <a class="source-link" href="__REPOSITORY_URL__">Source ↗</a>
      </div>
    </nav>

    <main>
      <header class="hero">
        <div class="hero-copy">
          <span class="status">Latest run indexed</span>
          <h1>Forge faster.<span>Prove it.</span></h1>
          <p class="lede">
            A live performance record for MerkleForge. Construction, proof generation,
            and verification measured across tree sizes and cryptographic hash functions.
          </p>
          <div class="hero-actions">
            <a class="primary" href="#results">Inspect dataset ↓</a>
            <a class="secondary" href="benchmarks/binary_tree/report/index.html">Raw reports</a>
          </div>
        </div>
        <div class="tree-stage" aria-label="Abstract binary Merkle tree topology">
          <svg class="tree-visual" viewBox="0 0 680 520" role="img">
            <g fill="none">
              <path class="tree-line hot" d="M340 76 180 190M340 76l160 114M180 190l-82 126M180 190l82 126M500 190l-82 126M500 190l82 126"/>
              <path class="tree-line" d="m98 316-45 108m45-108 45 108m119-108-45 108m45-108 45 108m111-108-45 108m45-108 45 108m119-108-45 108m45-108 45 108"/>
            </g>
            <text class="root-label" x="340" y="33" text-anchor="middle">ROOT HASH</text>
            <circle class="node root pulse" cx="340" cy="76" r="18"/>
            <circle class="node" cx="180" cy="190" r="14"/><circle class="node" cx="500" cy="190" r="14"/>
            <circle class="node" cx="98" cy="316" r="11"/><circle class="node" cx="262" cy="316" r="11"/>
            <circle class="node" cx="418" cy="316" r="11"/><circle class="node" cx="582" cy="316" r="11"/>
            <rect class="node leaf" x="43" y="414" width="20" height="20" rx="3"/>
            <rect class="node leaf" x="133" y="414" width="20" height="20" rx="3"/>
            <rect class="node leaf" x="207" y="414" width="20" height="20" rx="3"/>
            <rect class="node leaf" x="297" y="414" width="20" height="20" rx="3"/>
            <rect class="node leaf" x="363" y="414" width="20" height="20" rx="3"/>
            <rect class="node leaf" x="453" y="414" width="20" height="20" rx="3"/>
            <rect class="node leaf" x="527" y="414" width="20" height="20" rx="3"/>
            <rect class="node leaf" x="617" y="414" width="20" height="20" rx="3"/>
            <text class="node-label" x="53" y="458" text-anchor="middle">L0</text>
            <text class="node-label" x="143" y="458" text-anchor="middle">L1</text>
            <text class="node-label" x="217" y="458" text-anchor="middle">L2</text>
            <text class="node-label" x="307" y="458" text-anchor="middle">L3</text>
            <text class="node-label" x="373" y="458" text-anchor="middle">L4</text>
            <text class="node-label" x="463" y="458" text-anchor="middle">L5</text>
            <text class="node-label" x="537" y="458" text-anchor="middle">L6</text>
            <text class="node-label" x="627" y="458" text-anchor="middle">L7</text>
          </svg>
        </div>
      </header>

      <section class="run-strip" aria-label="Benchmark run metadata">
        <div class="run-cell"><span class="label">Reproduce this run</span><div class="command">$ cargo bench --bench binary_tree</div></div>
        <div class="run-cell"><span class="label">Harness</span><span class="run-value">Criterion.rs</span></div>
        <div class="run-cell"><span class="label">Confidence</span><span class="run-value">95%</span></div>
        <div class="run-cell"><span class="label">Commit</span><span class="run-value" id="commit">loading</span></div>
      </section>

      <section class="section">
        <div class="section-head">
          <div><span class="label">Run inventory / 01</span><h2>The benchmark surface at a glance.</h2></div>
          <p class="section-copy">This dashboard is generated directly from Criterion's machine-readable estimates after each successful benchmark workflow.</p>
        </div>
        <div class="stats" id="stats"></div>
      </section>

      <section class="section" id="results">
        <div class="section-head">
          <div><span class="label">Measured dataset / 02</span><h2>Every operation. Every hash. One view.</h2></div>
          <p class="section-copy">Lower duration is better. The signal bar is normalized against comparable samples with the same operation and leaf count.</p>
        </div>
        <div class="results-toolbar">
          <div class="controls" id="controls"></div>
          <span class="results-key">Mean latency / 95% confidence interval</span>
        </div>
        <div class="benchmark-grid" id="benchmark-grid"></div>
        <div class="empty" id="empty">No completed benchmark samples were found.</div>
      </section>
    </main>

    <footer>
      <span>MERKLEFORGE / GENERATED <span id="generated-at"></span></span>
      <span>RUNNER HARDWARE AFFECTS ABSOLUTE RESULTS</span>
    </footer>
  </div>

  <script>
    const data = __DATA__;
    const benchmarks = data.benchmarks;
    const operationKeys = [...new Set(benchmarks.map(item => item.operation_key))];
    const formatDuration = ns => {
      if (ns < 1e3) return `${ns.toFixed(1)} ns`;
      if (ns < 1e6) return `${(ns / 1e3).toFixed(2)} us`;
      if (ns < 1e9) return `${(ns / 1e6).toFixed(2)} ms`;
      return `${(ns / 1e9).toFixed(2)} s`;
    };
    const compact = value => new Intl.NumberFormat("en", {
      notation: "compact", maximumFractionDigits: 1
    }).format(value);
    const displaySize = value => {
      const number = Number(String(value).replaceAll(",", ""));
      return Number.isFinite(number) ? new Intl.NumberFormat("en").format(number) : value;
    };
    const operationLabel = key => key.replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());

    function renderStats() {
      const algorithms = new Set(benchmarks.map(item => item.algorithm));
      const sizes = new Set(benchmarks.map(item => item.size));
      const fastest = benchmarks.length
        ? benchmarks.reduce((best, item) => item.mean_ns < best.mean_ns ? item : best)
        : null;
      const stats = [
        ["Samples indexed", benchmarks.length, "completed benchmark cases"],
        ["Operations", operationKeys.length, "measured workflows"],
        ["Hash functions", algorithms.size, "pluggable algorithms"],
        ["Fastest signal", fastest ? formatDuration(fastest.mean_ns) : "n/a", fastest ? fastest.algorithm : "awaiting data"]
      ];
      document.querySelector("#stats").innerHTML = stats.map(([label, value, note]) => `
        <article class="stat-card">
          <span class="label">${label}</span>
          <strong class="stat-value">${value}</strong>
          <span class="stat-note">${note}</span>
        </article>
      `).join("");
    }

    function comparisonWidth(item) {
      const peers = benchmarks.filter(peer =>
        peer.operation_key === item.operation_key && peer.size === item.size
      );
      const slowest = Math.max(...peers.map(peer => peer.mean_ns));
      return slowest > 0 ? Math.max(8, (item.mean_ns / slowest) * 100) : 100;
    }

    function renderCards(filter = "all") {
      const visible = benchmarks
        .filter(item => filter === "all" || item.operation_key === filter)
        .sort((a, b) =>
          a.operation.localeCompare(b.operation)
          || a.size_value - b.size_value
          || a.mean_ns - b.mean_ns
        );
      document.querySelector("#empty").style.display = visible.length ? "none" : "block";
      document.querySelector("#benchmark-grid").innerHTML = visible.map((item, index) => `
        <article class="benchmark-card">
          <span class="index">${String(index + 1).padStart(2, "0")}</span>
          <div>
            <span class="label">Operation</span>
            <h3 class="operation">${item.operation}</h3>
            <span class="algorithm">${item.algorithm}</span>
          </div>
          <div class="measurement">
            <strong class="duration">${formatDuration(item.mean_ns)}</strong>
            <div class="track"><div class="bar" style="--width:${comparisonWidth(item).toFixed(1)}%"></div></div>
            <div class="confidence">CI ${formatDuration(item.lower_ns)} - ${formatDuration(item.upper_ns)}</div>
          </div>
          <div class="size"><small>Input</small>${displaySize(item.size)} leaves</div>
          <div>
            <span class="throughput"><small>Throughput</small>${item.elements_per_second ? compact(item.elements_per_second) + " leaves/s" : "latency only"}</span>
            <a class="report-link" href="${item.report}">Open report ↗</a>
          </div>
        </article>
      `).join("");
    }

    function renderControls() {
      const options = [["all", "All samples"], ...operationKeys.map(key => [key, operationLabel(key)])];
      const controls = document.querySelector("#controls");
      controls.innerHTML = options.map(([key, label], index) => `
        <button class="filter ${index === 0 ? "active" : ""}" data-filter="${key}">${label}</button>
      `).join("");
      controls.addEventListener("click", event => {
        const button = event.target.closest("[data-filter]");
        if (!button) return;
        controls.querySelectorAll(".filter").forEach(item => item.classList.remove("active"));
        button.classList.add("active");
        renderCards(button.dataset.filter);
      });
    }

    document.querySelector("#commit").textContent = data.commit;
    document.querySelector("#generated-at").textContent = new Date(data.generatedAt).toLocaleString();
    renderStats();
    renderControls();
    renderCards();
  </script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--criterion-dir", type=Path, default=Path("target/criterion"))
    parser.add_argument("--output", type=Path, default=Path("_site/index.html"))
    parser.add_argument(
        "--repository-url",
        default=os.environ.get(
            "GITHUB_SERVER_URL", "https://github.com"
        )
        + "/"
        + os.environ.get("GITHUB_REPOSITORY", "dicethedev/MerkleForge"),
    )
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    args = parser.parse_args()

    benchmarks = collect_benchmarks(args.criterion_dir)
    render_site(benchmarks, args.output, args.repository_url, args.commit)
    print(f"Generated {args.output} with {len(benchmarks)} benchmark samples")


if __name__ == "__main__":
    main()
