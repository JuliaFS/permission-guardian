import type { RiskSignal } from "./types";

// Helper: Проверяваме дали има официални платежни обекти в window
function detectPaymentGatewayObjects(): { hasStripe: boolean; hasPayPal: boolean; hasBraintree: boolean; hasKlarna: boolean; hasAdyen: boolean; hasSquare: boolean } {
  const win = typeof window !== "undefined" ? window : {};
  return {
    hasStripe: !!(win as any).Stripe || !!(win as any).StripeCheckout,
    hasPayPal: !!(win as any).paypal || !!(win as any).PAYPAL,
    hasBraintree: !!(win as any).braintree || !!(win as any).BraintreeSetupForm,
    hasKlarna: !!(win as any).Klarna || !!(win as any).klarna,
    hasAdyen: !!(win as any).AdyenCheckout || !!(win as any).adyenCheckout,
    hasSquare: !!(win as any).SqPaymentForm || !!(win as any).sq,
  };
}

// Helper: Разпознаваме официални платежни елементи по класове и data-атрибути
function detectOfficialPaymentElements(): {
  stripeElements: number;
  paypalButtons: number;
  braintreeElements: number;
  klarnaElements: number;
  adyenElements: number;
  squareElements: number;
  amazonPayElements: number;
  googlePayElements: number;
} {
  const doc = typeof document !== "undefined" ? document : null;
  if (!doc) return { stripeElements: 0, paypalButtons: 0, braintreeElements: 0, klarnaElements: 0, adyenElements: 0, squareElements: 0, amazonPayElements: 0, googlePayElements: 0 };

  return {
    stripeElements: doc.querySelectorAll('[class*="StripeElement"], [data-stripe], [id*="card-element"], [id*="stripe"]').length,
    paypalButtons: doc.querySelectorAll('[id*="paypal"], [data-paypal], button[data-funding-source]').length,
    braintreeElements: doc.querySelectorAll('[data-braintree], [class*="braintree"], [id*="braintree"]').length,
    klarnaElements: doc.querySelectorAll('[data-klarna], [class*="klarna"], [id*="klarna"]').length,
    adyenElements: doc.querySelectorAll('[data-adyen], [class*="adyen"], [id*="adyen"]').length,
    squareElements: doc.querySelectorAll('[data-sq], [class*="square"], [id*="sq-"]').length,
    amazonPayElements: doc.querySelectorAll('[data-amazon-pay], [class*="amazon-pay"], [id*="amazon"]').length,
    googlePayElements: doc.querySelectorAll('[data-google-pay], [class*="google-pay"], [id*="google-pay"]').length,
  };
}

// Helper: Проверяваме дали платежни елементи са вградени в официален iframe
function isPaymentFieldInOfficialIframe(field: HTMLInputElement): boolean {
  const iframe = field.closest("iframe");
  if (!iframe) return false;

  const src = iframe.getAttribute("src") || "";
  const trustedFrameSources = [
    // Stripe
    "js.stripe.com",
    "stripe.com",
    // PayPal
    "paypal.com",
    "www.paypal.com",
    // Braintree
    "braintreepayments.com",
    // Klarna
    "klarna.com",
    "klarna-payments.com",
    // Adyen
    "adyen.com",
    "checkoutshopper-",
    // Square
    "squareup.com",
    "web.squarecdn.com",
    // Mollie
    "mollie.com",
    // 2Checkout
    "2checkout.com",
    "verifone.com",
    // Amazon Pay
    "amazon-pay-",
    // Worldpay
    "worldpay.com",
    // Authorize.Net
    "authorize.net",
  ];

  return trustedFrameSources.some((trusted) => src.includes(trusted));
}

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

      // Проверяваме дали са използвани официални платежни системи
      const gatewayObjects = detectPaymentGatewayObjects();
      const officialElements = detectOfficialPaymentElements();

      const detectedGateways: string[] = [];
      if (gatewayObjects.hasStripe) detectedGateways.push("Stripe");
      if (gatewayObjects.hasPayPal) detectedGateways.push("PayPal");
      if (gatewayObjects.hasBraintree) detectedGateways.push("Braintree");
      if (gatewayObjects.hasKlarna) detectedGateways.push("Klarna");
      if (gatewayObjects.hasAdyen) detectedGateways.push("Adyen");
      if (gatewayObjects.hasSquare) detectedGateways.push("Square");

      if (detectedGateways.length > 0) {
        signals.push({
          id: "payment_gateway_official",
          message: `✅ This page uses official payment processors (${detectedGateways.join(", ")}). Payment data is handled securely.`,
          weight: -15, // NEGATIVE weight = reduces risk
          category: "Sensitive Data",
        });
      } else if (
        officialElements.stripeElements > 0 ||
        officialElements.paypalButtons > 0 ||
        officialElements.braintreeElements > 0 ||
        officialElements.klarnaElements > 0 ||
        officialElements.adyenElements > 0 ||
        officialElements.squareElements > 0 ||
        officialElements.amazonPayElements > 0 ||
        officialElements.googlePayElements > 0
      ) {
        const detectedElements: string[] = [];
        if (officialElements.stripeElements > 0) detectedElements.push("Stripe");
        if (officialElements.paypalButtons > 0) detectedElements.push("PayPal");
        if (officialElements.braintreeElements > 0) detectedElements.push("Braintree");
        if (officialElements.klarnaElements > 0) detectedElements.push("Klarna");
        if (officialElements.adyenElements > 0) detectedElements.push("Adyen");
        if (officialElements.squareElements > 0) detectedElements.push("Square");
        if (officialElements.amazonPayElements > 0) detectedElements.push("Amazon Pay");
        if (officialElements.googlePayElements > 0) detectedElements.push("Google Pay");

        signals.push({
          id: "payment_elements_official",
          message: `✅ Detected official payment form elements (${detectedElements.join(", ")} integration).`,
          weight: -10,
          category: "Sensitive Data",
        });
      }

      // Проверяваме дали полетата са в защитен iframe
      const paymentsInOfficialFrames = paymentInputs.filter((f) => isPaymentFieldInOfficialIframe(f)).length;
      if (paymentsInOfficialFrames > 0) {
        signals.push({
          id: "payment_fields_in_official_iframe",
          message: `✅ ${paymentsInOfficialFrames} payment field(s) are securely embedded in an official payment processor's iframe.`,
          weight: -20, // NEGATIVE = safe
          category: "Sensitive Data",
        });
      }

      const paymentForms = Array.from(
        new Set(
          paymentInputs
            .map((input) => input.closest("form"))
            .filter((form): form is HTMLFormElement => !!form),
        ),
      );

      const unsafeFieldPresent = paymentInputs.some((input) => input.closest('iframe') === null);
      // Only flag as unsafe if there are payment fields AND no official gateway detected
      if (unsafeFieldPresent && detectedGateways.length === 0 && officialElements.stripeElements === 0 && officialElements.paypalButtons === 0 && officialElements.braintreeElements === 0) {
        signals.push({
          id: "unsafe_card_fields",
          message:
            "🚨 Внимание: Полетата за кредитна карта са директно вградени в сайта, а не през защитен модул (Stripe/PayPal). Риск от скимър!",
          weight: 90,
          category: "Sensitive Data",
        });
      }

      const trustedPaymentHosts = [
        // Stripe
        "stripe.com",
        "api.stripe.com",
        "checkout.stripe.com",
        "js.stripe.com",
        // PayPal
        "paypal.com",
        "www.paypal.com",
        "checkout.paypal.com",
        // Braintree (PayPal subsidiary)
        "braintreepayments.com",
        "client.braintreegateway.com",
        // Klarna
        "klarna.com",
        "klarna-payments.com",
        "checkout.klarna.com",
        // Adyen
        "adyen.com",
        "checkout.adyen.com",
        "checkoutshopper-live.adyen.com",
        // Square
        "squareup.com",
        "web.squarecdn.com",
        "web-payments-sdk.squareup.com",
        // Mollie
        "mollie.com",
        "mollie.nl",
        "checkout.mollie.com",
        // 2Checkout / Verifone
        "2checkout.com",
        "verifone.com",
        "payment.verifone.com",
        // Authorize.Net
        "authorize.net",
        "accept.authorize.net",
        "frauddetection.authorize.net",
        // Amazon Pay
        "mws.amazonservices.com",
        "amazon-pay.amazon.com",
        "amazon-payments",
        // Apple Pay / Google Pay
        "apple.com",
        "google.com",
        "pay.google.com",
        // Worldpay / FIS
        "worldpay.com",
        "checkout.worldpay.com",
        // Global Collect / Ingenico
        "globalcollect.com",
        "ingenico.com",
        // 3D Secure
        "threeds.io",
        // SagePay
        "sagepay.com",
        "checkout.sagepay.com",
        // Wise (formerly TransferWise)
        "wise.com",
        // Mollie
        "mollie.com",
        // Payoneer
        "payoneer.com",
        // Skrill
        "skrill.com",
      ];

      const isTrustedOrigin = (origin: string) => {
        try {
          const parsed = new URL(origin);
          return trustedPaymentHosts.some(
            (trusted) =>
              parsed.hostname === trusted || parsed.hostname.endsWith(`.${trusted}`),
          );
        } catch {
          return false;
        }
      };

      const pageOrigin = window.location.origin;
      paymentForms.forEach((form) => {
        const action = form.action || window.location.href;
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.origin !== pageOrigin && !isTrustedOrigin(actionUrl.origin)) {
            signals.push({
              id: "payment_form_external_unknown_destination",
              message:
                "This payment form submits sensitive data to an unfamiliar external origin, which greatly increases the risk of card data exfiltration.",
              weight: 100,
              category: "Website Security",
            });
          } else if (actionUrl.origin !== pageOrigin) {
            signals.push({
              id: "payment_form_external_submit",
              message:
                "A payment form on this page submits to a different site, which can increase the risk of data misuse.",
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

  // Detect official payment-related scripts (NOT suspicious!)
  try {
    const officialPaymentScriptKeywords = [
      "js.stripe.com",
      "stripe",
      "paypal",
      "braintree",
      "klarna",
      "adyen",
      "square",
      "mollie",
      "authorize.net",
      "worldpay",
    ];
    const suspiciousScriptKeywords = [
      "crypto-js",
      "card-number",
      "jquery.payment",
      "securepay",
      "woocommerce",
      "payment-form",
      "skimmer",
      "keylogger",
    ];

    let officialPaymentScripts = 0;
    const officialScripts = pageScripts.filter((script) => {
      if (!script.src) return false;
      const normalized = script.src.toLowerCase();
      return officialPaymentScriptKeywords.some((keyword) => normalized.includes(keyword));
    });
    officialPaymentScripts = officialScripts.length;

    if (officialPaymentScripts > 0) {
      signals.push({
        id: "official_payment_script",
        message: `✅ Loaded ${officialPaymentScripts} official payment processor script(s) on the page.`,
        weight: -10, // NEGATIVE = reduces risk
        category: "Website Security",
      });
    }

    const suspiciousScripts = pageScripts.filter((script) => {
      if (!script.src) return false;
      const normalized = script.src.toLowerCase();
      // Don't flag official payment scripts as suspicious
      if (officialPaymentScriptKeywords.some((keyword) => normalized.includes(keyword))) {
        return false;
      }
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

  // OLD CODE (removed):
  // Detect suspicious payment-related scripts loaded by the page
  // try {
  //   const suspiciousScriptKeywords = [
  //     "crypto-js",
  //     "stripe",
  //     "payment",
  //     "checkout",
  //     "card-number",
  //     "jquery.payment",
  //     "securepay",
  //     "paypal",
  //     "woocommerce",
  //     "payment-form",
  //     "stripe-gateway",
  //   ];

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
