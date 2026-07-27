import type { ReactNode } from "react";
import { BrandMark } from "../components/BrandMark";
import type { Page, SiteData } from "../types/site";
import { assetPath } from "../utils/paths";

type AppLayoutProps = {
  page: Page;
  site: SiteData;
  children: ReactNode;
};

const nav = [
  ["docs", "Docs"],
  ["examples", "Examples"],
  ["benchmarks", "Benchmarks"],
] as const;

export function AppLayout({ page, site, children }: AppLayoutProps) {
  return (
    <div className="shell">
      <div className="top-ribbon">
        <span>MERKLEFORGE v{site.crateVersion}</span>
        <span>Binary · Sparse · Patricia</span>
      </div>
      <nav className="nav">
        <a className="brand" href={assetPath("index.html")}>
          <BrandMark />
          <span>
            MerkleForge
          </span>
        </a>
        <div className="nav-links">
          {nav.map(([key, label]) => (
            <a
              key={key}
              className={`nav-link ${page === key ? "active" : ""}`}
              href={assetPath(`${key}/`)}
            >
              {label}
            </a>
          ))}
          <a className="source-link" href={site.repositoryUrl} target="_blank" rel="noreferrer">
            GitHub
          </a>
        </div>
      </nav>
      {children}
    </div>
  );
}
