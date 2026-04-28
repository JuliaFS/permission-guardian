import type { RiskSignal } from "./types";

export function analyzeDOM(): RiskSignal[] {
  const signals: RiskSignal[] = [];

  const passwordField = document.querySelector('input[type="password"]');

  if (passwordField) {
    signals.push({
      id: "password_field",
      message: "This page is asking for your password",
      weight: 40,
      category: "Sensitive Data"
    });
  }

  return signals;
}