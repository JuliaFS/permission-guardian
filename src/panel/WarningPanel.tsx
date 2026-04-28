import type { RiskSignal } from "../engine/types";

export function WarningPanel({
  level,
  signals
}: {
  level: string;
  signals: RiskSignal[];
}) {
  return (
    <div className="guardian-panel">
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