import { useState } from "react";
import { CheckIcon } from "./icons/CheckIcon";
import { CopyIcon } from "./icons/CopyIcon";

type CodeWindowProps = {
  file?: string;
  meta?: string;
  code: string;
};

export function CodeWindow({ file, meta, code }: CodeWindowProps) {
  const [copied, setCopied] = useState(false);

  async function copyCode() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="code-window">
      <div className="code-head">
        <span>{file ?? "Terminal"}</span>
        <span>{meta}</span>
        <button
          className={copied ? "copy-code copied" : "copy-code"}
          type="button"
          onClick={copyCode}
          aria-label={copied ? "Code copied" : "Copy code"}
          title={copied ? "Copied" : "Copy code"}
        >
          {copied ? <CheckIcon className="copy-icon" /> : <CopyIcon className="copy-icon" />}
        </button>
      </div>
      <pre>
        <code>{code}</code>
      </pre>
    </div>
  );
}
