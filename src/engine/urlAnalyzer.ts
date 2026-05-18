import type { RiskSignal } from "./types";

export function analyzeUrl(url: string): RiskSignal[] {
  const signals: RiskSignal[] = [];

  let urlObj: URL | null = null;
  try {
    urlObj = new URL(url);
  } catch {
    urlObj = null;
  }

  if (urlObj?.protocol === "http:") {
    signals.push({
      id: "website_http_connection",
      message: "Connection is not secure (HTTP)",
      weight: 50,
      category: "Website Security",
    });
  }

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

  // Punycode / IDN (common in homograph phishing)
  const hostname = urlObj?.hostname ?? "";
  if (hostname.startsWith("xn--")) {
    signals.push({
      id: "url_punycode",
      message: "Domain uses punycode (IDN). This can hide look‑alike characters.",
      weight: 35,
      category: "URL Risk",
    });
  }

  // Redirect-style parameters
  const searchParams = urlObj?.searchParams;
  if (searchParams) {
    const redirectKeys = ["redirect", "redir", "redirect_uri", "redirect_url", "url", "target", "next", "continue", "return"];
    const hit = redirectKeys.find((k) => searchParams.has(k));
    if (hit) {
      signals.push({
        id: "url_redirect_param",
        message: `URL contains a redirect parameter (“${hit}”) which can be abused for phishing`,
        weight: 15,
        category: "URL Risk",
      });
    }
  }

  return signals;
}
