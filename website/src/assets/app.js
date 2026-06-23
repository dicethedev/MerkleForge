(() => {
  const currentPage = document.body.dataset.page;
  document.querySelectorAll("[data-nav]").forEach(link => {
    if (link.dataset.nav === currentPage) {
      link.classList.add("active");
    }
  });

  const data = window.MERKLEFORGE_BENCHMARKS;
  if (!data) return;

  const benchmarks = data.benchmarks;
  const operationKeys = [...new Set(benchmarks.map(item => item.operation_key))];
  const formatDuration = ns => {
    if (ns < 1e3) return `${ns.toFixed(1)} ns`;
    if (ns < 1e6) return `${(ns / 1e3).toFixed(2)} us`;
    if (ns < 1e9) return `${(ns / 1e6).toFixed(2)} ms`;
    return `${(ns / 1e9).toFixed(2)} s`;
  };
  const compact = value => new Intl.NumberFormat("en", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
  const displaySize = value => {
    const number = Number(String(value).replaceAll(",", ""));
    return Number.isFinite(number) ? new Intl.NumberFormat("en").format(number) : value;
  };
  const operationLabel = key => key
    .replaceAll("_", " ")
    .replace(/\b\w/g, char => char.toUpperCase());

  function renderStats() {
    const algorithms = new Set(benchmarks.map(item => item.algorithm));
    const fastest = benchmarks.length
      ? benchmarks.reduce((best, item) => item.mean_ns < best.mean_ns ? item : best)
      : null;
    const stats = [
      ["Samples indexed", benchmarks.length, "completed benchmark cases"],
      ["Operations", operationKeys.length, "measured workflows"],
      ["Hash functions", algorithms.size, "pluggable algorithms"],
      ["Fastest signal", fastest ? formatDuration(fastest.mean_ns) : "n/a", fastest ? fastest.algorithm : "awaiting data"],
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
        <div class="row-actions">
          <span class="throughput"><small>Throughput</small>${item.elements_per_second ? compact(item.elements_per_second) + " leaves/s" : "latency only"}</span>
          <a class="button secondary report-link" href="${item.report}">Open report ↗</a>
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
})();
