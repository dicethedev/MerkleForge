export type Page = "home" | "docs" | "examples" | "demo" | "benchmarks";

export type SiteData = {
  crateVersion: string;
  repositoryUrl: string;
  commit: string;
};

export type BenchmarkSample = {
  id: string;
  tree_variant?: string;
  operation: string;
  operation_key: string;
  algorithm: string;
  size: string;
  size_value: number;
  mean_ns: number;
  lower_ns: number;
  upper_ns: number;
  elements_per_second: number | null;
  report: string;
};

export type BenchmarkData = {
  benchmarks: BenchmarkSample[];
  generatedAt: string;
  commit: string;
};
