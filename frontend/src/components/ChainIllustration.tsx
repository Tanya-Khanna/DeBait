export function ChainIllustration({
  reducedMotion,
}: {
  reducedMotion: boolean;
}) {
  return (
    <div
      className={`chain ${reducedMotion ? "still" : ""}`}
      aria-label="Illustrative sequence connecting a call, message, managed browser and sandbox payment"
    >
      <div className="chain-head">
        <span>Illustrative sequence</span>
        <b>Signal follows context</b>
      </div>
      <svg viewBox="0 0 760 260" role="img">
        <title>A protected chain across four controlled app surfaces</title>
        <path
          className="trace"
          d="M86 82C170 82 158 180 255 180S330 82 425 82s83 98 172 98"
        />
        <g transform="translate(38 42)">
          <rect width="110" height="82" rx="20" />
          <text x="20" y="34">
            01 · CALL
          </text>
          <text x="20" y="58">
            Signal
          </text>
        </g>
        <g transform="translate(200 140)">
          <rect width="110" height="82" rx="20" />
          <text x="20" y="34">
            02 · CHAT
          </text>
          <text x="20" y="58">
            Evidence
          </text>
        </g>
        <g transform="translate(370 42)">
          <rect width="110" height="82" rx="20" />
          <text x="20" y="34">
            03 · WEB
          </text>
          <text x="20" y="58">
            Binding
          </text>
        </g>
        <g className="protect" transform="translate(550 140)">
          <rect width="170" height="82" rx="20" />
          <text x="20" y="34">
            04 · PAYMENT
          </text>
          <text x="20" y="58">
            Protect precisely
          </text>
        </g>
      </svg>
    </div>
  );
}
