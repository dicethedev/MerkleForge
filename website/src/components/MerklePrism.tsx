export function MerklePrism() {
  return (
    <div className="prism-stage" aria-label="MerkleForge proof and root illustration">
      <div className="prism-glow" />
      <svg className="prism-visual" viewBox="0 0 620 560" role="img">
        <defs>
          <linearGradient id="forge-root" x1="0%" x2="100%" y1="0%" y2="100%">
            <stop offset="0%" stopColor="#ecfeff" />
            <stop offset="45%" stopColor="#37d6e6" />
            <stop offset="100%" stopColor="#adff5c" />
          </linearGradient>
          <linearGradient id="proof-rail" x1="0%" x2="100%" y1="0%" y2="0%">
            <stop offset="0%" stopColor="#37d6e6" />
            <stop offset="58%" stopColor="#8b5cf6" />
            <stop offset="100%" stopColor="#adff5c" />
          </linearGradient>
          <linearGradient id="state-plane" x1="0%" x2="100%" y1="0%" y2="100%">
            <stop offset="0%" stopColor="#082d33" />
            <stop offset="55%" stopColor="#101827" />
            <stop offset="100%" stopColor="#1f1638" />
          </linearGradient>
          <filter id="soft-shadow" x="-40%" y="-40%" width="180%" height="180%">
            <feDropShadow dx="0" dy="24" stdDeviation="20" floodColor="#37d6e6" floodOpacity=".22" />
          </filter>
        </defs>

        <rect className="forge-panel panel-left" x="42" y="86" width="168" height="354" rx="26" />
        <rect className="forge-panel panel-right" x="410" y="86" width="168" height="354" rx="26" />
        <path className="state-plane" d="M310 188 478 286 310 384 142 286 310 188Z" />
        <path className="state-plane state-plane-back" d="M310 250 498 360 310 470 122 360 310 250Z" />

        <path className="tree-link" d="M310 110 214 196M310 110l96 86M214 196l-56 78M214 196l60 78M406 196l-60 78M406 196l56 78" />
        <path className="proof-link" d="M158 274 274 274 310 110 406 196 462 274" />
        <path className="proof-tracer" d="M158 274 274 274 310 110 406 196 462 274" />
        <path className="witness-link" d="M82 340 C150 306 203 326 263 378 S405 447 532 382" />
        <path className="witness-tracer" d="M82 340 C150 306 203 326 263 378 S405 447 532 382" />

        <g className="leaf-stack">
          <rect x="70" y="140" width="94" height="30" rx="10" />
          <rect x="70" y="182" width="118" height="30" rx="10" />
          <rect x="70" y="224" width="82" height="30" rx="10" />
          <text x="94" y="160">DATA</text>
          <text x="94" y="202">KEY</text>
          <text x="94" y="244">VALUE</text>
        </g>

        <circle className="forge-node root" cx="310" cy="110" r="22" />
        <circle className="forge-node" cx="214" cy="196" r="14" />
        <circle className="forge-node" cx="406" cy="196" r="14" />
        <circle className="forge-node leaf selected" cx="158" cy="274" r="12" />
        <circle className="forge-node leaf" cx="274" cy="274" r="12" />
        <circle className="forge-node leaf" cx="346" cy="274" r="12" />
        <circle className="forge-node leaf selected" cx="462" cy="274" r="12" />

        <g className="root-card">
          <rect x="408" y="126" width="128" height="52" rx="16" />
          <text x="432" y="148">ROOT</text>
          <text x="432" y="164">0x8f3a...</text>
        </g>
        <g className="proof-card">
          <rect x="406" y="328" width="132" height="88" rx="18" />
          <text x="430" y="354">VERIFY</text>
          <path d="M433 380l17 17 43-45" />
        </g>

        <g className="variant-chip chip-binary">
          <rect x="70" y="328" width="116" height="34" rx="12" />
          <text x="128" y="350" textAnchor="middle">BINARY</text>
        </g>
        <g className="variant-chip chip-sparse">
          <rect x="68" y="378" width="122" height="34" rx="12" />
          <text x="129" y="400" textAnchor="middle">SPARSE</text>
        </g>
        <g className="variant-chip chip-patricia">
          <rect x="236" y="428" width="148" height="34" rx="12" />
          <text x="310" y="450" textAnchor="middle">PATRICIA</text>
        </g>

        <circle className="spark spark-a" cx="158" cy="274" r="4" />
        <circle className="spark spark-b" cx="310" cy="110" r="4" />
        <circle className="spark spark-c" cx="462" cy="274" r="4" />
        <text className="layer-label" x="310" y="315" textAnchor="middle">PROOF PATH</text>
        <text className="layer-label muted" x="310" y="404" textAnchor="middle">STATE COMMITMENT</text>
      </svg>
    </div>
  );
}
