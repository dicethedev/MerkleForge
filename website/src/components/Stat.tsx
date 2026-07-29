type StatProps = {
  label: string;
  value: string;
  note: string;
};

export function Stat({ label, value, note }: StatProps) {
  return (
    <article className="stat-card">
      <span className="label">{label}</span>
      <strong className="stat-value">{value}</strong>
      <span className="stat-note">{note}</span>
    </article>
  );
}
