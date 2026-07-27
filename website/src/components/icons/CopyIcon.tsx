type CopyIconProps = {
  className?: string;
};

export function CopyIcon({ className }: CopyIconProps) {
  return (
    <svg
      className={className}
      aria-hidden="true"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M6 5.25C6 4.56 6.56 4 7.25 4H11.75C12.44 4 13 4.56 13 5.25V11.75C13 12.44 12.44 13 11.75 13H7.25C6.56 13 6 12.44 6 11.75V5.25Z"
        stroke="currentColor"
        strokeLinejoin="round"
      />
      <path
        d="M4 10.5H3.75C3.06 10.5 2.5 9.94 2.5 9.25V4.25C2.5 3.56 3.06 3 3.75 3H8.25C8.94 3 9.5 3.56 9.5 4.25V4.5"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
