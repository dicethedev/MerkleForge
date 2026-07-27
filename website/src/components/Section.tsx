import type { ReactNode } from "react";

type SectionProps = {
  label: string;
  title: string;
  copy?: string;
  children: ReactNode;
};

export function Section({ label, title, copy, children }: SectionProps) {
  return (
    <section className="section">
      <div className="section-head">
        <div>
          <span className="label">{label}</span>
          <h2>{title}</h2>
        </div>
        {copy ? <p className="section-copy">{copy}</p> : null}
      </div>
      {children}
    </section>
  );
}
