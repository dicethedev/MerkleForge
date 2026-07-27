import type { ReactNode } from "react";
import { assetPath } from "../utils/paths";
import { ArrowUpRightIcon } from "./icons/ArrowUpRightIcon";

type FeatureCardProps = {
  number: string;
  title: string;
  link: string;
  linkText: string;
  visual?: "hash" | "proof" | "chart";
  children: ReactNode;
};

export function FeatureCard({ number, title, link, linkText, visual, children }: FeatureCardProps) {
  return (
    <article className="card">
      <div className="card-copy">
        <span className="card-number">{number}</span>
        <h3>{title}</h3>
        <p>{children}</p>
        <a className="card-link" href={assetPath(link)}>
          {linkText}
          <ArrowUpRightIcon className="link-icon" />
        </a>
      </div>
      {visual ? <CardVisual visual={visual} /> : null}
    </article>
  );
}

function CardVisual({ visual }: { visual: NonNullable<FeatureCardProps["visual"]> }) {
  return (
    <div className={`card-visual ${visual}`} aria-hidden="true">
      {visual === "hash" ? (
        <>
          <span />
          <span />
          <span />
        </>
      ) : null}
      {visual === "proof" ? (
        <>
          <i />
          <i />
          <i />
          <i />
        </>
      ) : null}
      {visual === "chart" ? (
        <>
          <b />
          <b />
          <b />
        </>
      ) : null}
    </div>
  );
}
