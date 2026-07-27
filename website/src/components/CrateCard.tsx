import type { ReactNode } from "react";
import { ArrowUpRightIcon } from "./icons/ArrowUpRightIcon";

type CrateCardProps = {
  badge: string;
  name: string;
  docs: string;
  visual: "core" | "hash" | "trees";
  children: ReactNode;
};

export function CrateCard({ badge, name, docs, visual, children }: CrateCardProps) {
  return (
    <article className="crate-card">
      <div className="crate-copy">
        <span className="badge">{badge}</span>
        <h3>{name}</h3>
        <p>{children}</p>
        <a className="card-link" href={docs} target="_blank" rel="noreferrer">
          API docs
          <ArrowUpRightIcon className="link-icon" />
        </a>
      </div>
      <CrateVisual visual={visual} />
    </article>
  );
}

function CrateVisual({ visual }: { visual: CrateCardProps["visual"] }) {
  return (
    <div className={`crate-visual ${visual}`} aria-hidden="true">
      {visual === "core" ? (
        <>
          <span />
          <span />
          <span />
          <span />
        </>
      ) : null}
      {visual === "hash" ? (
        <>
          <i />
          <i />
          <i />
        </>
      ) : null}
      {visual === "trees" ? (
        <>
          <b />
          <b />
          <b />
          <b />
          <b />
        </>
      ) : null}
    </div>
  );
}
