import { useMemo, useState } from "react";

type CommandPanelProps = {
  crateVersion: string;
};

export function CommandPanel({ crateVersion }: CommandPanelProps) {
  const [mode, setMode] = useState<"cargo" | "toml">("cargo");
  const [copied, setCopied] = useState(false);
  const commands = useMemo(
    () => ({
      cargo: `cargo add merkle-core@${crateVersion} merkleforge-hash@${crateVersion} merkle-variants@${crateVersion}`,
      toml: `[dependencies]
merkle-core = "${crateVersion}"
merkleforge-hash = "${crateVersion}"
merkle-variants = "${crateVersion}"`,
    }),
    [crateVersion],
  );
  const activeCommand = commands[mode];

  async function copyCommand() {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(activeCommand);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = activeCommand;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="command-panel" aria-label="Install MerkleForge crates">
      <div className="command-tabs">
        <button
          className={`command-tab ${mode === "cargo" ? "active" : ""}`}
          type="button"
          onClick={() => setMode("cargo")}
        >
          cargo add
        </button>
        <button
          className={`command-tab ${mode === "toml" ? "active" : ""}`}
          type="button"
          onClick={() => setMode("toml")}
        >
          Cargo.toml
        </button>
        <button className="copy-command" type="button" onClick={copyCommand}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="command-code">
        <code>{activeCommand}</code>
      </pre>
      <span className="copy-status" aria-live="polite">
        {copied ? "Install command copied to clipboard." : "Click a tab, then copy the install command."}
      </span>
    </div>
  );
}
