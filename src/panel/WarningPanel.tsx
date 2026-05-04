import type { RiskSignal } from "../engine/types";

export function WarningPanel({
  level,
  signals,
  onClose,
  showCloseButton,
}: {
  level: string;
  signals: RiskSignal[];
  onClose: () => void;
  showCloseButton: boolean;
}) {
  return (
    <div className="guardian-panel">
      {showCloseButton ? (
        <button
          type="button"
          className="guardian-panel__close"
          aria-label="Close Permission Guardian panel"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onClose();
          }}
        >
          ×
        </button>
      ) : null}
      <h3>🛡️ Permission Guardian</h3>

      <p>
        Risk Level: <strong>{level}</strong>
      </p>

      {/* 👇 THIS is where your snippet goes */}
      <h4>Why this is risky:</h4>
      <ul>
        {signals.map((s) => (
          <li key={s.id}>👉 {s.message}</li>
        ))}
      </ul>
    </div>
  );
}
