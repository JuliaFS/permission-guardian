import type { RiskSignal } from "./types";

export function analyzeUrl(url: string): RiskSignal[] {
  const signals: RiskSignal[] = [];

  if (url.includes("@")) {
    signals.push({
      id: "url_at_symbol",
      message: "URL contains '@' which can hide the real destination",
      weight: 30,
      category: "URL Risk"
    });
  }

  if (url.length > 120) {
    signals.push({
      id: "url_length",
      message: "URL is unusually long",
      weight: 20,
      category: "URL Risk"
    });
  }

  if (/(\d{1,3}\.){3}\d{1,3}/.test(url)) {
    signals.push({
      id: "ip_address",
      message: "Uses IP address instead of domain",
      weight: 40,
      category: "URL Risk"
    });
  }

  return signals;
}