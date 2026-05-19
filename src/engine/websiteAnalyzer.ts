import type { RiskSignal } from "./types";

// Топ брандове, които най-често биват имитирани от фишинг сайтове
const TOP_BRANDS = [
  "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
  "paypal.com", "netflix.com", "instagram.com", "linkedin.com", "twitter.com"
];

// Подозрителни безплатни или евтини топ-левъл домейни (TLDs)
const SUSPICIOUS_TLDS = [".top", ".xyz", ".club", ".live", ".click", ".info", ".gq", ".tk", ".ml"];

/**
 * Изчислява дистанцията на Левенщайн между два стринга (колко промени са нужни, за да съвпаднат).
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
        message: "Връзката не е шифрирана (HTTP). Сайтът може да подслушва данните ви.",
        weight: 35,
        category: "Website Security",
      });
    }

    // 2. Структурен анализ (Замества Domain Age симулацията)
    // Фишинг сайтовете често имат твърде много субдомейни или тирета
    const dashCount = (hostname.match(/-/g) || []).length;
    const dotCount = (hostname.match(/\./g) || []).length;

    if (dashCount > 3 || dotCount > 4) {
      signals.push({
        id: "website_suspicious_structure",
        message: "Структурата на линка изглежда необичайно дълга и подозрителна.",
        weight: 45,
        category: "Website Reputation",
      });
    }

    // Проверка за евтини/опасни TLDs
    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
      signals.push({
        id: "website_risky_tld",
        message: "Сайтът използва домейни с ниска репутация, често ползвани за спам.",
        weight: 25,
        category: "Website Reputation",
      });
    }

    // 3. Динамичен Тайпоскуотинг чрез Левенщайн (Несимулиран)
    for (const brand of TOP_BRANDS) {
      if (hostname === brand) break; // Сайтът е истинският бранд

      // Ако името силно прилича на известен бранд (дистанция 1 или 2 букви разлика)
      // Пример: "g00gle.com" или "googly.com"
      const distance = getLevenshteinDistance(hostname, brand);
      if (distance > 0 && distance <= 2) {
        signals.push({
          id: "website_typosquatting",
          message: `Внимание! Този сайт имитира известната марка "${brand}" (Засечена е визуална прилика).`,
          weight: 85,
          category: "Website Impersonation",
        });
        break;
      }

      // Проверка за поддомейн капан: напр. "paypal.com.fake-site.com"
      if (hostname.includes(brand) && !hostname.endsWith("." + brand)) {
        signals.push({
          id: "website_brand_spoofing",
          message: `Името на легитимна компания (${brand}) е скрито вътре в адреса. Почти сигурен фишинг.`,
          weight: 95,
          category: "Website Impersonation",
        });
        break;
      }
    }

    // 4. Known phishing lists (offline check; list is cached by background)
    if (options?.knownPhishing) {
      signals.push({
        id: "website_phishing_list",
        message: "Сайтът е докладван и присъства в световните черни списъци за фишинг.",
        weight: 100,
        category: "Website Security",
      });
    }

  } catch (error) {
    console.error("Грешка при анализа на URL:", error);
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
