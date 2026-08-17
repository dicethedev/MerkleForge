import React, { useMemo } from "react";
import { createRoot } from "react-dom/client";
import "./assets/styles.css";
import { benchmarkFallback, defaultSiteData } from "./data/defaults";
import { useJson } from "./hooks/useJson";
import { BenchmarksPage } from "./pages/BenchmarksPage";
import { DemoPage } from "./pages/DemoPage";
import { DocsPage } from "./pages/DocsPage";
import { ExamplesPage } from "./pages/ExamplesPage";
import { HomePage } from "./pages/HomePage";
import type { BenchmarkData, SiteData } from "./types/site";
import { currentPage } from "./utils/paths";

function App() {
  const site = useJson<SiteData>("site-data.json", defaultSiteData);
  const fallback = useMemo<BenchmarkData>(() => benchmarkFallback(site.commit), [site.commit]);
  const benchmarks = useJson<BenchmarkData>("benchmark-data.json", fallback);

  switch (currentPage()) {
    case "docs":
      return <DocsPage site={site} />;
    case "examples":
      return <ExamplesPage site={site} />;
    case "demo":
      return <DemoPage site={site} />;
    case "benchmarks":
      return <BenchmarksPage site={site} benchmarks={benchmarks} />;
    default:
      return <HomePage site={site} />;
  }
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
