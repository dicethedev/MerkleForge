type ArrowUpRightIconProps = {
  className?: string;
};

export function ArrowUpRightIcon({ className }: ArrowUpRightIconProps) {
  return (
    <svg
      className={className}
      aria-hidden="true"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path d="M5 4.5H11.5V11" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M4.5 11.5L11.25 4.75" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
