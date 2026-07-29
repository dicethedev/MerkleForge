import type { Page } from "../types/site";

export const basePath = import.meta.env.BASE_URL;

export function assetPath(path: string): string {
  return `${basePath}${path.replace(/^\/+/, "")}`;
}

export function currentPage(): Page {
  const escapedBase = basePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const relative = window.location.pathname
    .replace(new RegExp(`^${escapedBase}`), "")
    .replace(/^\/+|\/+$/g, "");

  if (relative === "docs") return "docs";
  if (relative === "examples") return "examples";
  if (relative === "benchmarks") return "benchmarks";
  return "home";
}
