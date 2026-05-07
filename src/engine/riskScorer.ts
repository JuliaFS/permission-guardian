import type { RiskSignal, RiskLevel } from "./types";

export function calculateRisk(signals: RiskSignal[]): {
  score: number;
  level: RiskLevel;
} {
  const score = signals.reduce((sum, s) => sum + s.weight, 0);

  let level: RiskLevel = "LOW";

  if (score > 120) level = "CRITICAL";
  else if (score > 70) level = "HIGH";
  else if (score > 40) level = "MEDIUM";

  return { score, level };
}
