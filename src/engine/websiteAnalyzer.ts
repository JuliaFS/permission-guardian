import type { RiskSignal } from "./types";

/**
 * Evaluates the safety of a given URL based on various signals.
 * @param url The URL to analyze.
 * @returns An array of RiskSignal objects.
 */
export function analyzeWebsite(url: string): RiskSignal[] {
  const signals: RiskSignal[] = [];
  const urlObj = new URL(url);
  const hostname = urlObj.hostname;

  // 1. HTTP vs HTTPS
  if (urlObj.protocol === "http:") {
    signals.push({
      id: "website_http_connection",
      message: "Connection is not secure (HTTP)",
      weight: 50,
      category: "Website Security",
    });
  }

  // 2. Domain age (simulated)
  // In a real extension, this would involve an external API call or a pre-compiled list.
  // For demonstration, we'll assume certain patterns indicate new/risky domains.
  const simulatedNewDomainPatterns = ["new-site-", "free-offer-", "promo-"];
  if (simulatedNewDomainPatterns.some(pattern => hostname.includes(pattern))) {
    signals.push({
      id: "website_new_domain",
      message: "This domain appears to be very new or recently registered.",
      weight: 40,
      category: "Website Reputation",
    });
  }

  // 3. Typosquatting (simulated)
  // This is a highly complex problem. A real solution would involve:
  // - A list of popular domains (e.g., google.com, facebook.com, amazon.com)
  // - Levenshtein distance or other string similarity algorithms
  // - Homoglyph detection (e.g., using Unicode characters that look similar)
  // For this example, we'll use a very basic check for common typos.
  const popularDomains = ["google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com"];
  const commonTypos = {
    "g00gle.com": "google.com",
    "faceb00k.com": "facebook.com",
    "amzon.com": "amazon.com",
    "micros0ft.com": "microsoft.com",
    "app1e.com": "apple.com",
    "googl.com": "google.com",
    "facebok.com": "facebook.com",
  };

  const normalizedHostname = hostname.replace(/^www\./, '');
  for (const typo in commonTypos) {
    if (normalizedHostname === typo) {
      signals.push({
        id: "website_typosquatting",
        message: `This site may be impersonating "${commonTypos[typo]}" (typosquatting detected).`,
        weight: 80,
        category: "Website Impersonation",
      });
      break;
    }
  }

  // 4. Known phishing lists (simulated - Google Safe Browsing API)
  // In a real extension, this would involve calling the Google Safe Browsing API.
  // For this example, we'll simulate a check against a small, static list.
  const simulatedPhishingDomains = ["malicious-phishing.com", "scam-login.net"];
  if (simulatedPhishingDomains.includes(hostname)) {
    signals.push({
      id: "website_phishing_list",
      message: "This site is on a known phishing list.",
      weight: 100,
      category: "Website Security",
    });
  }

  return signals;
}