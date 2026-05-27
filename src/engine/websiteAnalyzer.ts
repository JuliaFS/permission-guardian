import type { RiskSignal } from "./types";

// Top brands that are commonly impersonated by phishing sites
const TOP_BRANDS = [
  "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
  "paypal.com", "netflix.com", "instagram.com", "linkedin.com", "twitter.com"
];

// Suspicious free/cheap top-level domains (TLDs) often used for spam/phishing
const SUSPICIOUS_TLDS = [".top", ".xyz", ".club", ".live", ".click", ".info", ".gq", ".tk", ".ml"];

/**
 * Computes the Levenshtein distance between two strings
 * (how many edits are required to transform one into the other).
 */
function getLevenshteinDistance(a: string, b: string): number {
  const tmp = [];
  for (let i = 0; i <= a.length; i++) tmp[i] = [i];
  for (let j = 0; j <= b.length; j++) tmp[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      tmp[i][j] = Math.min(
        tmp[i - 1][j] + 1,
        tmp[i][j - 1] + 1,
        tmp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return tmp[a.length][b.length];
}

export function analyzeWebsite(url: string, options?: { knownPhishing?: boolean }): RiskSignal[] {
  const signals: RiskSignal[] = [];
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');

    // 1. HTTP vs HTTPS Connection
    if (urlObj.protocol === "http:") {
      signals.push({
        id: "website_http_connection",
        message: "Connection is not encrypted (HTTP). The site traffic can be intercepted or modified.",
        weight: 35,
        category: "Website Security",
      });
    }

    // 2. Structural analysis (lightweight heuristic)
    // Phishing sites often use too many subdomains or hyphens.
    const dashCount = (hostname.match(/-/g) || []).length;
    const dotCount = (hostname.match(/\./g) || []).length;

    if (dashCount > 3 || dotCount > 4) {
      signals.push({
        id: "website_suspicious_structure",
        message: "The hostname structure looks unusually long or complex, which can be a phishing indicator.",
        weight: 45,
        category: "Website Reputation",
      });
    }

    // Check for risky TLDs
    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
      signals.push({
        id: "website_risky_tld",
        message: "This site uses a low-reputation TLD that is often abused for spam/phishing.",
        weight: 25,
        category: "Website Reputation",
      });
    }

    // 3. Typosquatting detection using Levenshtein distance
    for (const brand of TOP_BRANDS) {
      if (hostname === brand) break; // The site is the real brand domain

      // If the name is very close to a popular brand (distance 1–2 edits),
      // it can be an impersonation attempt (e.g. "g00gle.com", "googly.com").
      const distance = getLevenshteinDistance(hostname, brand);
      if (distance > 0 && distance <= 2) {
        signals.push({
          id: "website_typosquatting",
          message: `Warning: this site looks like it is impersonating the brand "${brand}".`,
          weight: 85,
          category: "Website Impersonation",
        });
        break;
      }

      // Check for a subdomain trap, e.g. "paypal.com.fake-site.com"
      if (hostname.includes(brand) && !hostname.endsWith("." + brand)) {
        signals.push({
          id: "website_brand_spoofing",
          message: `A legitimate brand name (${brand}) is embedded in the URL, which is a common phishing trick.`,
          weight: 95,
          category: "Website Impersonation",
        });
        break;
      }
    }

    const suspiciousPaymentPaths = [
      "/wp-content/plugins/angler-stripe-gateway",
      "/wp-content/plugins/stripe",
      "/wp-content/plugins/woocommerce",
      "/wp-content/plugins/paypal",
      "/wp-content/plugins/payment",
      "/wp-content/plugins/stripe-gateway",
      "/checkout",
      "/payment",
      "/billing",
      "/order",
      "crypto-js.min.js",
      "jquery.payment",
      "payment-form",
      "securepay",
    ];

    const lowerPath = urlObj.pathname.toLowerCase();
    const lowerUrl = url.toLowerCase();
    const isSuspiciousPaymentPath = suspiciousPaymentPaths.some((pattern) =>
      lowerPath.includes(pattern) || lowerUrl.includes(pattern),
    );

    if (isSuspiciousPaymentPath) {
      signals.push({
        id: "website_suspicious_payment_infrastructure",
        message: "This URL contains payment-related or plugin paths that are often used by fake checkout or card-stealing pages.",
        weight: 60,
        category: "Website Reputation",
      });
    }

    // 4. Known phishing lists (offline check; list is cached by background)
    if (options?.knownPhishing) {
      signals.push({
        id: "website_phishing_list",
        message: "The site is reported in phishing blocklists.",
        weight: 100,
        category: "Website Security",
      });
    }

  } catch (error) {
    console.error("Error while analyzing URL:", error);
  }

  return signals;
}

//simulated signals
// import type { RiskSignal } from "./types";

// /**
//  * Evaluates the safety of a given URL based on various signals.
//  * @param url The URL to analyze.
//  * @returns An array of RiskSignal objects.
//  */
// export function analyzeWebsite(url: string): RiskSignal[] {
//   const signals: RiskSignal[] = [];
//   const urlObj = new URL(url);
//   const hostname = urlObj.hostname;

//   // 1. HTTP vs HTTPS
//   if (urlObj.protocol === "http:") {
//     signals.push({
//       id: "website_http_connection",
//       message: "Connection is not secure (HTTP)",
//       weight: 50,
//       category: "Website Security",
//     });
//   }

//   // 2. Domain age (simulated)
//   // In a real extension, this would involve an external API call or a pre-compiled list.
//   // For demonstration, we'll assume certain patterns indicate new/risky domains.
//   const simulatedNewDomainPatterns = ["new-site-", "free-offer-", "promo-"];
//   if (simulatedNewDomainPatterns.some(pattern => hostname.includes(pattern))) {
//     signals.push({
//       id: "website_new_domain",
//       message: "This domain appears to be very new or recently registered.",
//       weight: 40,
//       category: "Website Reputation",
//     });
//   }

//   // 3. Typosquatting (simulated)
//   // This is a highly complex problem. A real solution would involve:
//   // - A list of popular domains (e.g., google.com, facebook.com, amazon.com)
//   // - Levenshtein distance or other string similarity algorithms
//   // - Homoglyph detection (e.g., using Unicode characters that look similar)
//   // For this example, we'll use a very basic check for common typos.
//   const commonTypos: Record<string, string> = {
//     "g00gle.com": "google.com",
//     "faceb00k.com": "facebook.com",
//     "amzon.com": "amazon.com",
//     "micros0ft.com": "microsoft.com",
//     "app1e.com": "apple.com",
//     "googl.com": "google.com",
//     "facebok.com": "facebook.com",
//   };

//   const normalizedHostname = hostname.replace(/^www\./, '');
//   for (const typo in commonTypos) {
//     if (normalizedHostname === typo) {
//       signals.push({
//         id: "website_typosquatting",
//         message: `This site may be impersonating "${commonTypos[typo]}" (typosquatting detected).`,
//         weight: 80,
//         category: "Website Impersonation",
//       });
//       break;
//     }
//   }

//   // 4. Known phishing lists (simulated - Google Safe Browsing API)
//   // In a real extension, this would involve calling the Google Safe Browsing API.
//   // For this example, we'll simulate a check against a small, static list.
//   const simulatedPhishingDomains = ["malicious-phishing.com", "scam-login.net"];
//   if (simulatedPhishingDomains.includes(hostname)) {
//     signals.push({
//       id: "website_phishing_list",
//       message: "This site is on a known phishing list.",
//       weight: 100,
//       category: "Website Security",
//     });
//   }

//   return signals;
// }
