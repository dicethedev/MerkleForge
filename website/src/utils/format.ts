export function formatDuration(ns: number): string {
  if (ns < 1e3) return `${ns.toFixed(1)} ns`;
  if (ns < 1e6) return `${(ns / 1e3).toFixed(2)} us`;
  if (ns < 1e9) return `${(ns / 1e6).toFixed(2)} ms`;
  return `${(ns / 1e9).toFixed(2)} s`;
}

export function compact(value: number): string {
  return new Intl.NumberFormat("en", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
}

export function displaySize(value: string): string {
  const number = Number(value.replaceAll(",", ""));
  return Number.isFinite(number) ? new Intl.NumberFormat("en").format(number) : value;
}

export function operationLabel(key: string): string {
  const labels: Record<string, string> = {
    batch_update_batch_insert: "Batch insert",
    batch_update_sequential_insert: "Sequential insert",
    construction: "Construction",
    insert: "Insert",
    non_membership_generation: "Non-membership proof",
    non_membership_verification: "Non-membership verify",
    proof_generation: "Proof generation",
    proof_verification: "Proof verification",
  };

  if (labels[key]) return labels[key];
  return key.replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());
}
