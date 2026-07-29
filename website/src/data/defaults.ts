import type { BenchmarkData, SiteData } from "../types/site";

export const defaultSiteData: SiteData = {
  crateVersion: "0.4.0",
  repositoryUrl: "https://github.com/dicethedev/MerkleForge",
  commit: "local",
};

export function benchmarkFallback(commit: string): BenchmarkData {
  return {
    benchmarks: [],
    generatedAt: new Date().toISOString(),
    commit,
  };
}
