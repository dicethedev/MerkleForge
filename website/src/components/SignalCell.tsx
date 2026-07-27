import type { ReactNode } from "react";

type SignalCellProps = {
  label: string;
  value: ReactNode;
};

export function SignalCell({ label, value }: SignalCellProps) {
  return (
    <div className="signal-cell">
      <span className="label">{label}</span>
      <span className="signal-value">{value}</span>
    </div>
  );
}
