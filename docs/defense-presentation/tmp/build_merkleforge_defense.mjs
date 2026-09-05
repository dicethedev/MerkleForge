import fs from "node:fs/promises";
import path from "node:path";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const ROOT = "/home/dice/Projects/MerkleForge";
const OUT = path.join(ROOT, "docs/defense-presentation/merkleforge-final-defense.pptx");
const ASSETS = path.join(ROOT, "docs/assets/session-four");
const W = 1280;
const H = 720;

const C = {
  bg: "#06080d",
  panel: "#0d131d",
  panel2: "#101826",
  ink: "#f5f8ff",
  muted: "#94a3b8",
  dim: "#64748b",
  cyan: "#22d3ee",
  green: "#a3ff3d",
  purple: "#8b5cf6",
  orange: "#fb923c",
  line: "#203044",
};

async function writeBlob(filePath, blob) {
  await fs.writeFile(filePath, new Uint8Array(await blob.arrayBuffer()));
}

async function imageBytes(name) {
  return fs.readFile(path.join(ASSETS, name));
}

function addText(slide, text, x, y, w, h, opts = {}) {
  const shape = slide.shapes.add({
    geometry: "textbox",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  shape.text = text;
  shape.text.style = {
    fontSize: opts.size ?? 22,
    bold: opts.bold ?? false,
    color: opts.color ?? C.ink,
    alignment: opts.align ?? "left",
  };
  return shape;
}

function addPanel(slide, x, y, w, h, fill = C.panel) {
  return slide.shapes.add({
    geometry: "roundRect",
    position: { left: x, top: y, width: w, height: h },
    fill,
    line: { style: "solid", fill: C.line, width: 1 },
    borderRadius: "rounded-2xl",
  });
}

function addEyebrow(slide, text) {
  addText(slide, text, 72, 44, 640, 28, {
    size: 14,
    bold: true,
    color: C.cyan,
  });
}

function addTitle(slide, title, subtitle = "") {
  addText(slide, title, 72, 86, 840, 104, {
    size: 38,
    bold: true,
    color: C.ink,
  });
  if (subtitle) {
    addText(slide, subtitle, 72, 178, 850, 66, {
      size: 20,
      color: C.muted,
    });
  }
}

function addFooter(slide, n) {
  slide.shapes.add({
    geometry: "line",
    position: { left: 72, top: 662, width: 1136, height: 0 },
    fill: "none",
    line: { style: "solid", fill: "#182536", width: 1 },
  });
  addText(slide, "MerkleForge final year project defense", 72, 674, 520, 24, {
    size: 12,
    color: C.dim,
  });
  addText(slide, String(n).padStart(2, "0"), 1168, 674, 40, 24, {
    size: 12,
    bold: true,
    color: C.cyan,
    align: "right",
  });
}

function addBullets(slide, items, x, y, w, gap = 58) {
  items.forEach((item, index) => {
    const top = y + index * gap;
    slide.shapes.add({
      geometry: "ellipse",
      position: { left: x, top: top + 8, width: 10, height: 10 },
      fill: item.color ?? C.cyan,
      line: { style: "solid", fill: "none", width: 0 },
    });
    addText(slide, item.title, x + 26, top, w - 26, 28, {
      size: 21,
      bold: true,
      color: C.ink,
    });
    addText(slide, item.body, x + 26, top + 30, w - 26, 44, {
      size: 16,
      color: C.muted,
    });
  });
}

async function addImage(slide, name, x, y, w, h, fit = "cover") {
  slide.images.add({
    blob: await imageBytes(name),
    contentType: "image/png",
    alt: name,
    fit,
    position: { left: x, top: y, width: w, height: h },
    geometry: "roundRect",
    borderRadius: "rounded-2xl",
  });
}

function setNotes(slide, text) {
  slide.speakerNotes.textFrame.setText(text);
  slide.speakerNotes.setVisible(true);
}

async function main() {
  await fs.mkdir(path.dirname(OUT), { recursive: true });
  const p = Presentation.create({ slideSize: { width: W, height: H } });

  let s = p.slides.add();
  s.background.fill = C.bg;
  addText(s, "MerkleForge", 72, 80, 660, 80, { size: 62, bold: true });
  addText(
    s,
    "Building a faster, unified data verification toolkit for modern blockchains.",
    72,
    166,
    760,
    72,
    { size: 24, color: C.muted },
  );
  addText(s, "Blessing Omosehin Samuel", 72, 520, 420, 34, { size: 24, bold: true });
  addText(s, "Software Engineering - Miva Open University - August 2026", 72, 558, 620, 30, {
    size: 17,
    color: C.muted,
  });
  addPanel(s, 790, 96, 360, 430, "#07111a");
  addText(s, "Binary", 848, 154, 180, 32, { size: 28, bold: true, color: C.cyan });
  addText(s, "Sparse", 848, 266, 180, 32, { size: 28, bold: true, color: C.green });
  addText(s, "Patricia", 848, 378, 180, 32, { size: 28, bold: true, color: C.purple });
  for (const [x, y, c] of [
    [1045, 165, C.cyan],
    [1010, 277, C.green],
    [1075, 389, C.purple],
    [990, 445, C.orange],
  ]) {
    s.shapes.add({ geometry: "ellipse", position: { left: x, top: y, width: 28, height: 28 }, fill: c, line: { style: "solid", fill: "none", width: 0 } });
  }
  addFooter(s, 1);
  setNotes(s, "[Sources]\nProject documentation PDF supplied by the author.\nRepository: https://github.com/dicethedev/MerkleForge");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "INTRODUCTION");
  addTitle(s, "The problem is fragmented Merkle tooling.", "Blockchain systems need fast proofs, but Rust developers often combine separate libraries for binary, sparse, and Patricia trees.");
  addBullets(s, [
    { title: "Different tree types, different APIs", body: "Developers must switch mental models and dependencies when moving between transaction batches, sparse state maps, and Ethereum-style state.", color: C.cyan },
    { title: "Research rarely reaches usable crates", body: "Optimizations such as empty-hash caches, shortcut nodes, and batch updates are discussed in papers but are not always available in developer tools.", color: C.green },
    { title: "Benchmarks are hard to compare", body: "Without one repeatable benchmark suite, choosing a hash function or tree variant becomes guesswork.", color: C.orange },
  ], 94, 278, 1000, 82);
  addFooter(s, 2);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 1, Statement of the Problem.\nResearch background referenced in the project: Nakamoto, Merkle, Ma et al., Kuznetsov et al.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "AIM AND OBJECTIVES");
  addTitle(s, "MerkleForge unifies proofs under one Rust API.", "The project delivers a typed, modular toolkit for building, proving, verifying, and measuring Merkle data structures.");
  const objectives = [
    ["1", "Design one trait-driven architecture"],
    ["2", "Implement binary, sparse, and Patricia variants"],
    ["3", "Support SHA-256, Keccak-256, and BLAKE3"],
    ["4", "Benchmark against existing solutions"],
    ["5", "Publish documentation, examples, and crates"],
  ];
  objectives.forEach(([num, label], i) => {
    const x = 100 + (i % 3) * 360;
    const y = 294 + Math.floor(i / 3) * 132;
    addPanel(s, x, y, 310, 90, "#0b141f");
    addText(s, num, x + 24, y + 21, 42, 42, { size: 32, bold: true, color: C.cyan });
    addText(s, label, x + 76, y + 24, 200, 42, { size: 19, bold: true });
  });
  addFooter(s, 3);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 1, Aim and Objectives of the Study.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "LITERATURE GAP");
  addTitle(s, "The gap is between theory and practical tooling.", "Merkle tree research improves proof size, update cost, and hashing speed, but implementation support remains scattered.");
  addPanel(s, 90, 282, 318, 210, "#0e1623");
  addPanel(s, 482, 282, 318, 210, "#0e1623");
  addPanel(s, 874, 282, 318, 210, "#0e1623");
  addText(s, "Academic progress", 124, 322, 250, 34, { size: 24, bold: true, color: C.green });
  addText(s, "Batch updates, shortcut nodes, sparse proofs, and faster hashing reduce verification overhead.", 124, 368, 232, 86, { size: 17, color: C.muted });
  addText(s, "Developer reality", 516, 322, 250, 34, { size: 24, bold: true, color: C.orange });
  addText(s, "Existing Rust tools often focus on one variant or expose incompatible APIs.", 516, 368, 232, 86, { size: 17, color: C.muted });
  addText(s, "MerkleForge answer", 908, 322, 250, 34, { size: 24, bold: true, color: C.cyan });
  addText(s, "One workspace combines variants, hash adapters, proofs, docs, and benchmarks.", 908, 368, 232, 86, { size: 17, color: C.muted });
  addFooter(s, 4);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 2, Literature Review and research gap discussion.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "SYSTEM ARCHITECTURE");
  addTitle(s, "The implementation is split into small crates.", "Each crate has one responsibility, which keeps the system easier to test, document, and extend.");
  const crates = [
    ["merkle-core", "Traits, proof types, metadata, errors", 160, 278, C.cyan],
    ["merkleforge-hash", "SHA-256, Keccak-256, BLAKE3 adapters", 482, 278, C.green],
    ["merkle-variants", "Binary, sparse, and Patricia implementations", 804, 278, C.purple],
    ["merkle-bench", "Criterion benchmarks and comparisons", 322, 440, C.orange],
    ["website", "Docs, examples, benchmarks, live demo", 644, 440, C.cyan],
  ];
  crates.forEach(([name, body, x, y, color]) => {
    addPanel(s, x, y, 300, 110, "#0b141f");
    addText(s, name, x + 24, y + 22, 250, 30, { size: 23, bold: true, color });
    addText(s, body, x + 24, y + 58, 245, 42, { size: 15, color: C.muted });
  });
  addFooter(s, 5);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 4, System Implementation.\nRepository workspace layout.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "IMPLEMENTATION");
  addTitle(s, "Three tree variants cover three real use cases.", "The library exposes familiar operations while allowing each structure to use the storage model that fits its problem.");
  addBullets(s, [
    { title: "Binary Merkle Tree", body: "Best for ordered lists such as transactions, files, logs, and block batches.", color: C.cyan },
    { title: "Sparse Merkle Tree", body: "Best for huge key spaces where most entries are empty and absence proofs matter.", color: C.green },
    { title: "Merkle Patricia Trie", body: "Best for Ethereum-compatible account, storage, receipt, and state-root workflows.", color: C.purple },
  ], 100, 286, 610, 92);
  addPanel(s, 760, 260, 330, 270, "#07111a");
  addText(s, "Common workflow", 800, 302, 250, 36, { size: 25, bold: true });
  addText(s, "insert data\ncompute root\ngenerate proof\nverify statelessly", 800, 360, 240, 120, { size: 22, color: C.muted });
  addFooter(s, 6);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 4, implemented modules and tree variants.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "CODE EVIDENCE");
  addTitle(s, "The trait contract is the center of the design.", "All tree variants are built around a shared interface for mutation, queries, proof generation, metadata, and stateless verification.");
  addPanel(s, 88, 258, 550, 326, "#050a12");
  addText(s, "MerkleTree<H>", 126, 294, 300, 32, {
    size: 26,
    bold: true,
    color: C.cyan,
  });
  addText(
    s,
    "insert(data)\nremove(index)\nroot()\nleaf_count()\ngenerate_proof(index)\nmetadata()",
    126,
    346,
    462,
    186,
    { size: 24, color: C.ink },
  );
  addPanel(s, 690, 258, 500, 326, "#050a12");
  addText(s, "ProofVerifier<H>", 728, 294, 320, 32, {
    size: 26,
    bold: true,
    color: C.green,
  });
  addText(
    s,
    "fn verify(\n    expected_root: &H::Digest,\n    leaf_data: &[u8],\n    proof: &MerkleProof<H::Digest>,\n) -> bool;",
    728,
    350,
    390,
    134,
    { size: 19, color: C.ink },
  );
  addText(
    s,
    "This enables light-client verification: the verifier only needs the trusted root, the target data, and the proof path.",
    728,
    504,
    386,
    48,
    { size: 17, color: C.muted },
  );
  addText(s, "Source: merkle-core/src/traits/merkle_tree.rs", 126, 606, 560, 22, {
    size: 13,
    color: C.dim,
  });
  addFooter(s, 7);
  setNotes(s, "[Sources]\nTrait signatures summarized from merkle-core/src/traits/merkle_tree.rs in the project repository.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "METHODOLOGY");
  addTitle(s, "The project used iterative, evidence-driven development.", "Each phase added a working feature, then backed it with tests, docs, and benchmarks before moving forward.");
  addBullets(s, [
    { title: "Build", body: "Implement the core crate, hash adapters, tree variant, and public API.", color: C.cyan },
    { title: "Verify", body: "Run unit, integration, property-based, and Ethereum vector tests.", color: C.green },
    { title: "Measure", body: "Use Criterion benchmarks, comparison suites, and energy-aware notes.", color: C.orange },
    { title: "Publish", body: "Expose docs, examples, release automation, website pages, and live demo.", color: C.purple },
  ], 104, 274, 930, 78);
  addFooter(s, 8);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 4, System Development and Testing Strategies.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "TESTING STRATEGY");
  addTitle(s, "Correctness was tested at multiple levels.", "The test suite checks single components, combined workflows, generated random cases, and Ethereum compatibility.");
  const tests = [
    ["Unit tests", "Core functions, errors, hashing, RLP, and tree operations"],
    ["Integration tests", "Combined modules across binary, sparse, and Patricia workflows"],
    ["Property tests", "Randomized invariants using Proptest"],
    ["Ethereum vectors", "Patricia trie roots checked against official test data"],
  ];
  tests.forEach(([name, body], i) => {
    const x = i % 2 === 0 ? 94 : 676;
    const y = i < 2 ? 286 : 438;
    addPanel(s, x, y, 510, 104, "#0b141f");
    addText(s, name, x + 28, y + 22, 240, 30, { size: 24, bold: true, color: i % 2 === 0 ? C.cyan : C.green });
    addText(s, body, x + 28, y + 58, 430, 34, { size: 16, color: C.muted });
  });
  addFooter(s, 9);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 4.3 Testing Strategies and Chapter 4.4 Test Cases and Results.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "TEST RESULTS");
  addTitle(s, "The implementation passed the recorded verification checks.", "The report records successful workspace, property, vector, documentation, and website checks.");
  const results = [
    ["merkle-core", "15 passed"],
    ["merkleforge-hash", "21 passed"],
    ["merkle-variants unit", "105 passed"],
    ["binary properties", "6 passed"],
    ["Patricia vectors", "3 passed"],
    ["website build", "passed"],
  ];
  results.forEach(([name, value], i) => {
    const x = 102 + (i % 3) * 360;
    const y = 282 + Math.floor(i / 3) * 128;
    addPanel(s, x, y, 300, 86, "#0b141f");
    addText(s, value, x + 26, y + 18, 240, 30, { size: 25, bold: true, color: C.green });
    addText(s, name, x + 26, y + 52, 240, 22, { size: 15, color: C.muted });
  });
  addFooter(s, 10);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 4.3 and Chapter 4.4 local testing results.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "PERFORMANCE EVALUATION");
  addTitle(s, "Benchmarks show where each design is strongest.", "Criterion measurements were used to compare hashing throughput, tree construction, proof generation, and verification.");
  addPanel(s, 90, 270, 340, 245, "#0b141f");
  addText(s, "Hashing", 122, 304, 250, 32, { size: 24, bold: true, color: C.cyan });
  addText(s, "BLAKE3 reached the strongest large-input throughput in the recorded benchmark: 5.99 GiB/s.", 122, 354, 260, 88, { size: 17, color: C.muted });
  addPanel(s, 470, 270, 340, 245, "#0b141f");
  addText(s, "Binary tree", 502, 304, 250, 32, { size: 24, bold: true, color: C.green });
  addText(s, "100K-leaf construction completed in about 268 ms with SHA-256 in the recorded run.", 502, 354, 260, 88, { size: 17, color: C.muted });
  addPanel(s, 850, 270, 340, 245, "#0b141f");
  addText(s, "Comparison", 882, 304, 250, 32, { size: 24, bold: true, color: C.orange });
  addText(s, "MerkleForge remained competitive on proof size and proof verification while offering more variants.", 882, 354, 260, 88, { size: 17, color: C.muted });
  addFooter(s, 11);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 4.5 Performance Evaluation and benchmark tables.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "USER INTERFACE");
  addTitle(s, "The website makes the artifact easier to evaluate.", "The React and Vite website turns the library into something reviewers can inspect without reading every source file first.");
  await addImage(s, "home-page.png", 88, 260, 350, 250, "cover");
  await addImage(s, "docs-page.png", 468, 260, 350, 250, "cover");
  await addImage(s, "demo-page.png", 848, 260, 350, 250, "cover");
  addText(s, "Landing page", 118, 530, 250, 24, { size: 17, bold: true });
  addText(s, "Docs", 498, 530, 250, 24, { size: 17, bold: true });
  addText(s, "Live demo", 878, 530, 250, 24, { size: 17, bold: true });
  addFooter(s, 12);
  setNotes(s, "[Sources]\nScreenshots generated from the local MerkleForge website build.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "HOW TO TEST");
  addTitle(s, "The panel can verify the artefact with standard commands.", "These commands reproduce the main quality checks and demonstrate stateless proof verification.");
  const commands = [
    "git clone https://github.com/dicethedev/MerkleForge.git",
    "cargo test --workspace",
    "cargo doc --workspace --no-deps",
    "cargo run -p merkle-variants --example light_client",
    "cargo bench --bench comparison",
    "npm --prefix website run build",
  ];
  addPanel(s, 92, 260, 1096, 314, "#050a12");
  commands.forEach((cmd, i) => {
    addText(s, `$ ${cmd}`, 128, 292 + i * 44, 980, 32, {
      size: 20,
      color: i === 3 ? C.green : C.ink,
    });
  });
  addFooter(s, 13);
  setNotes(s, "[Sources]\nProject documentation PDF: Chapter 4.6 Application Manual.");

  s = p.slides.add();
  s.background.fill = C.bg;
  addEyebrow(s, "CONCLUSION");
  addTitle(s, "MerkleForge meets the project goal.", "It provides a unified Rust toolkit for authenticated data structures, backed by tests, benchmarks, documentation, and a live demo.");
  addBullets(s, [
    { title: "Technical contribution", body: "A modular Rust workspace covering binary, sparse, and Ethereum-compatible Patricia structures.", color: C.cyan },
    { title: "Evidence contribution", body: "Tests, Ethereum vectors, Criterion benchmarks, screenshots, and report-ready documentation.", color: C.green },
    { title: "Practical contribution", body: "A public developer-facing artifact that can be installed, tested, benchmarked, and extended.", color: C.purple },
  ], 120, 298, 950, 82);
  addText(s, "Ready for defense and supervisor review.", 120, 592, 760, 36, { size: 26, bold: true, color: C.green });
  addFooter(s, 14);
  setNotes(s, "[Sources]\nProject documentation PDF: conclusion synthesized from the completed implementation, testing evidence, and application manual.");

  for (const [index, slide] of p.slides.items.entries()) {
    const png = await p.export({ slide, format: "png", scale: 1 });
    await writeBlob(path.join(ROOT, `docs/defense-presentation/rendered/slide-${String(index + 1).padStart(2, "0")}.png`), png);
  }
  const montage = await p.export({ format: "webp", montage: true, scale: 1 });
  await writeBlob(path.join(ROOT, "docs/defense-presentation/rendered/montage.webp"), montage);
  const pptx = await PresentationFile.exportPptx(p);
  await pptx.save(OUT);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
