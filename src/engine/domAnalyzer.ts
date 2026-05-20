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

  // Cookies (readable via document.cookie; does not include HttpOnly cookies)
  try {
    const cookieStr = typeof document.cookie === "string" ? document.cookie : "";
    const cookieCount = cookieStr ? cookieStr.split(";").filter(Boolean).length : 0;
    if (cookieCount > 0) {
      signals.push({
        id: "site_cookies_present",
        message: `This site has set ${cookieCount} readable cookie${cookieCount === 1 ? "" : "s"} in your browser`,
        weight: cookieCount >= 8 ? 20 : 10,
        category: "Tracking & Storage",
      });
    }
  } catch {
    // ignore
  }

  // Local/session storage (current state snapshot)
  try {
    const localCount = globalThis.localStorage ? globalThis.localStorage.length : 0;
    if (localCount > 0) {
      signals.push({
        id: "site_localstorage_present",
        message: `This site stored ${localCount} item${localCount === 1 ? "" : "s"} in localStorage`,
        weight: localCount >= 20 ? 20 : 10,
        category: "Tracking & Storage",
      });
    }

    const sessionCount = globalThis.sessionStorage ? globalThis.sessionStorage.length : 0;
    if (sessionCount > 0) {
      signals.push({
        id: "site_sessionstorage_present",
        message: `This site stored ${sessionCount} item${sessionCount === 1 ? "" : "s"} in sessionStorage`,
        weight: sessionCount >= 20 ? 12 : 6,
        category: "Tracking & Storage",
      });
    }
  } catch {
    // ignore
  }

  // Third-party scripts (rough tracker/ads indicator)
  let pageScripts: HTMLScriptElement[] = [];
  try {
    const currentHost = window.location.hostname;
    pageScripts = Array.from(document.scripts);
    const thirdParty = pageScripts.filter((s) => {
      if (!s.src) return false;
      try {
        const u = new URL(s.src, window.location.href);
        return !!u.hostname && u.hostname !== currentHost;
      } catch {
        return false;
      }
    });

    if (thirdParty.length >= 10) {
      signals.push({
        id: "third_party_scripts_high",
        message: `Loads many third-party scripts (${thirdParty.length}) which can increase tracking`,
        weight: thirdParty.length >= 25 ? 25 : 12,
        category: "Tracking & Storage",
      });
    }
  } catch {
    // ignore
  }

  // Detect payment-related forms and fields
  try {
    const candidateInputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    const paymentTerms = [
      "card",
      "credit",
      "cc-number",
      "cc-csc",
      "cc-cvv",
      "security code",
      "cvc",
      "cvv",
      "expiry",
      "expiration",
      "payment",
      "billing",
      "stripe",
      "paypal",
      "checkout",
      "bank",
    ];

    function getInputContext(input: HTMLInputElement) {
      const labels: string[] = [];
      if (input.id) {
        const label = document.querySelector(`label[for="${input.id}"]`);
        if (label?.textContent) labels.push(label.textContent);
      }
      return [
        input.name,
        input.id,
        input.placeholder,
        input.getAttribute("aria-label"),
        input.getAttribute("title"),
        ...labels,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
    }

    const paymentInputs = candidateInputs.filter((input) => {
      const context = getInputContext(input);
      const autocomplete = (input.autocomplete || "").toLowerCase();
      if (autocomplete.startsWith("cc-") || /cc-(name|number|exp|csc|cvv)/.test(autocomplete)) {
        return true;
      }
      return paymentTerms.some((term) => context.includes(term));
    });

    if (paymentInputs.length > 0) {
      signals.push({
        id: "payment_data_entry",
        message: `This page contains ${paymentInputs.length} field(s) that may collect credit card or payment data.`,
        weight: 55,
        category: "Sensitive Data",
      });

      const paymentForms = Array.from(
        new Set(
          paymentInputs
            .map((input) => input.closest("form"))
            .filter((form): form is HTMLFormElement => !!form),
        ),
      );

      paymentForms.forEach((form) => {
        const action = form.action || window.location.href;
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.origin !== window.location.origin) {
            signals.push({
              id: "payment_form_external_submit",
              message: "A payment form on this page submits to a different site, which can increase the risk of data misuse.",
              weight: 65,
              category: "Website Security",
            });
          }
        } catch {
          // ignore malformed form action
        }
      });
    }
  } catch {
    // ignore
  }

  // Detect suspicious payment-related scripts loaded by the page
  try {
    const suspiciousScriptKeywords = [
      "crypto-js",
      "stripe",
      "payment",
      "checkout",
      "card-number",
      "jquery.payment",
      "securepay",
      "paypal",
      "woocommerce",
      "payment-form",
      "stripe-gateway",
    ];
    const currentHost = window.location.hostname;
    const suspiciousScripts = pageScripts.filter((script) => {
      if (!script.src) return false;
      const normalized = script.src.toLowerCase();
      return suspiciousScriptKeywords.some((keyword) => normalized.includes(keyword));
    });

    if (suspiciousScripts.length > 0) {
      signals.push({
        id: "suspicious_payment_script",
        message: `Loaded ${suspiciousScripts.length} suspicious payment-related script(s) on the page.`,
        weight: 45,
        category: "Website Reputation",
      });
    }
  } catch {
    // ignore
  }

  // Cross-site iframes (ads, widgets, trackers)
  try {
    const currentHost = window.location.hostname;
    const frames = Array.from(document.querySelectorAll("iframe[src]"));
    const crossOriginFrames = frames.filter((f) => {
      const src = f.getAttribute("src");
      if (!src) return false;
      try {
        const u = new URL(src, window.location.href);
        return !!u.hostname && u.hostname !== currentHost;
      } catch {
        return false;
      }
    });
    if (crossOriginFrames.length >= 3) {
      signals.push({
        id: "third_party_iframes",
        message: `Embeds ${crossOriginFrames.length} third-party iframe${crossOriginFrames.length === 1 ? "" : "s"} (ads/widgets can track)`,
        weight: crossOriginFrames.length >= 8 ? 18 : 10,
        category: "Tracking & Storage",
      });
    }
  } catch {
    // ignore
  }

  return signals;
}
