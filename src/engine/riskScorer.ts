import type { RiskSignal, RiskLevel } from "./types";

export function calculateRisk(signals: RiskSignal[]): {
  score: number;
  level: RiskLevel;
} {
  if (!signals || signals.length === 0) {
    return { score: 0, level: "low" };
  }

  const categoryCaps: Record<string, number> = {
    "Sensitive Data": 80,
    "Website Security": 90,
    "Tracking & Storage": 20,
    "Website Reputation": 40,
  };

  const categoryModifiers: Record<string, number> = {
    "Tracking & Storage": 0.6,
  };

  const categoryTotals: Record<string, number> = {};
  signals.forEach((signal) => {
    const category = signal.category || "Tracking & Storage";
    const weight = Number.isFinite(signal.weight) ? signal.weight : 0;
    categoryTotals[category] = (categoryTotals[category] ?? 0) + weight;
  });

  let rawRisk = 0;
  for (const category in categoryTotals) {
    const totalWeight = categoryTotals[category];
    const cappedWeight = Math.min(totalWeight, categoryCaps[category] ?? 30);
    const modifier = categoryModifiers[category] ?? 1;
    rawRisk += cappedWeight * modifier;
  }

  rawRisk = Math.max(0, rawRisk);
  const score = Math.max(0, Math.min(100, Math.round(rawRisk)));

  let level: RiskLevel = "low";
  if (score > 40) level = "high";
  else if (score > 15) level = "medium";

  return { score, level };
}
