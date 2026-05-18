import type { RiskSignal, RiskLevel } from "./types";

export function calculateRisk(signals: RiskSignal[]): {
  score: number;
  level: RiskLevel;
} {
  // Convert "risk weight" into a 0..100 "safety score" where 100 is safest.
  // Exponential decay keeps the score meaningful even when many signals stack up.
  const totalWeight = signals.reduce((sum, s) => sum + (Number.isFinite(s.weight) ? s.weight : 0), 0);
  const score = Math.max(0, Math.min(100, Math.round(100 * Math.exp(-totalWeight / 100))));

  let level: RiskLevel = "low";

  if (score < 30) level = "critical";
  else if (score < 50) level = "high";
  else if (score < 70) level = "medium";

  return { score, level };
}
