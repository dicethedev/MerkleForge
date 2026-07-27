import type { CSSProperties } from "react";
import type { BenchmarkSample } from "../types/site";
import { assetPath } from "../utils/paths";
import { compact, displaySize, formatDuration } from "../utils/format";
import { ArrowUpRightIcon } from "./icons/ArrowUpRightIcon";

type BenchmarkCardProps = {
  item: BenchmarkSample;
  index: number;
  samples: BenchmarkSample[];
};

export function BenchmarkCard({ item, index, samples }: BenchmarkCardProps) {
  const peers = samples.filter(
    peer => peer.operation_key === item.operation_key && peer.size === item.size,
  );
  const slowest = Math.max(...peers.map(peer => peer.mean_ns));
  const width = slowest > 0 ? Math.max(8, (item.mean_ns / slowest) * 100) : 100;

  return (
    <article className="benchmark-card">
      <span className="index">{String(index + 1).padStart(2, "0")}</span>
      <div>
        <span className="label">What ran</span>
        <h3 className="operation">{item.operation}</h3>
        <span className="benchmark-context">
          {item.tree_variant ? `${item.tree_variant} / ` : ""}
          {item.algorithm}
        </span>
      </div>
      <div className="measurement">
        <span className="label">Time</span>
        <strong className="duration">{formatDuration(item.mean_ns)}</strong>
        <div className="track">
          <div className="bar" style={{ "--width": `${width.toFixed(1)}%` } as CSSProperties} />
        </div>
        <div className="confidence">
          likely range: {formatDuration(item.lower_ns)} - {formatDuration(item.upper_ns)}
        </div>
      </div>
      <div className="size">
        <small>Data size</small>
        {displaySize(item.size)} leaves
      </div>
      <div className="row-actions">
        <span className="throughput">
          <small>Speed</small>
          {item.elements_per_second ? `${compact(item.elements_per_second)} leaves/s` : "latency only"}
        </span>
        <a className="button secondary report-link" href={assetPath(item.report)}>
          Open raw report
          <ArrowUpRightIcon className="link-icon" />
        </a>
      </div>
    </article>
  );
}
