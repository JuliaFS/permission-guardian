import type { RiskSignal } from "./types";

// Helper: Check for official payment gateway objects in the window object
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

// Helper: Detect official payment form elements in the DOM (e.g., Stripe Elements, PayPal buttons)
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

// Helper: Check if an input field is embedded inside an official processor's iframe
function isPaymentFieldInOfficialIframe(field: HTMLInputElement): boolean {
  const iframe = field.closest("iframe");
  if (!iframe) return false;

  const src = iframe.getAttribute("src") || "";
  const trustedFrameSources = [
    "js.stripe.com", "stripe.com",
    "paypal.com", "www.paypal.com",
    "braintreepayments.com",
    "klarna.com", "klarna-payments.com",
    "adyen.com", "checkoutshopper-",
    "squareup.com", "web.squarecdn.com",
    "mollie.com", "2checkout.com", "verifone.com",
    "amazon-pay-", "worldpay.com", "authorize.net"
  ];

  return trustedFrameSources.some((trusted) => src.includes(trusted));
}

export function analyzeDOM(): RiskSignal[] {
  const signals: RiskSignal[] = [];

  // 1. Password Field Detection
  const passwordField = document.querySelector('input[type="password"]');
  if (passwordField) {
    signals.push({
      id: "password_field",
      message: "This page is asking for a password or sensitive authentication token.",
      weight: 40,
      category: "Sensitive Data"
    });
  }

  // 2. Cookie Analysis
  try {
    const cookieStr = typeof document.cookie === "string" ? document.cookie : "";
    const cookieCount = cookieStr ? cookieStr.split(";").filter(Boolean).length : 0;
    if (cookieCount >= 8) {
      const weight = cookieCount >= 20 ? 8 : 5;
      signals.push({
        id: "site_cookies_present",
        message: `This site has stored ${cookieCount} cookies in your browser. This is common for login and preferences, but it also increases the data stored by the site.`,
        weight,
        category: "Tracking & Storage",
      });
    }
  } catch { /* ignore */ }

  // 3. Web Storage Analysis (LocalStorage & SessionStorage)
  try {
    const localCount = globalThis.localStorage ? globalThis.localStorage.length : 0;
    if (localCount >= 10) {
      const weight = localCount >= 20 ? 8 : 5;
      signals.push({
        id: "site_localstorage_present",
        message: `This site has stored ${localCount} values in localStorage. This is normal for many sites, but persistent storage can also be used for tracking or profiling.`,
        weight,
        category: "Tracking & Storage",
      });
    }

    const sessionCount = globalThis.sessionStorage ? globalThis.sessionStorage.length : 0;
    if (sessionCount >= 10) {
      const weight = sessionCount >= 20 ? 4 : 2;
      signals.push({
        id: "site_sessionstorage_present",
        message: `This site has stored ${sessionCount} values in sessionStorage. That is usually used for current page state, but it still increases the browser-side surface area.`,
        weight,
        category: "Tracking & Storage",
      });
    }
  } catch { /* ignore */ }

  // 4. Third-Party Script Tracking
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

    if (thirdParty.length >= 15) {
      signals.push({
        id: "third_party_scripts_high",
        message: `Loads a high volume of third-party scripts (${thirdParty.length}), which is normal for rich sites but also increases tracking and supply-chain risk.`,
        weight: thirdParty.length >= 25 ? 16 : 10,
        category: "Tracking & Storage",
      });
    }
  } catch { /* ignore */ }

  // 5. Payment Forms and Fields Deep Analysis
  try {
    // Optimization: Filter out hidden, buttons, checkboxes right away to increase performance
    const candidateInputs = Array.from(document.querySelectorAll<HTMLInputElement>(
      'input[type="text"], input[type="number"], input[type="tel"], input:not([type])'
    ));

    const paymentTerms = [
      "card", "credit", "cc-number", "cc-csc", "cc-cvv", "security code",
      "cvc", "cvv", "expiry", "expiration", "payment", "billing",
      "stripe", "paypal", "checkout", "bank"
    ];

    function getInputContext(input: HTMLInputElement) {
      const labels: string[] = [];
      if (input.id) {
        const label = document.querySelector(`label[for="${input.id}"]`);
        if (label?.textContent) labels.push(label.textContent);
      }
      return [
        input.name, input.id, input.placeholder,
        input.getAttribute("aria-label"), input.getAttribute("title"), ...labels
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
        message: `This page contains ${paymentInputs.length} fields matching payment or credit card patterns.`,
        weight: 55,
        category: "Sensitive Data",
      });

      const gatewayObjects = detectPaymentGatewayObjects();
      const officialElements = detectOfficialPaymentElements();

      const detectedGateways: string[] = [];
      if (gatewayObjects.hasStripe) detectedGateways.push("Stripe");
      if (gatewayObjects.hasPayPal) detectedGateways.push("PayPal");
      if (gatewayObjects.hasBraintree) detectedGateways.push("Braintree");
      if (gatewayObjects.hasKlarna) detectedGateways.push("Klarna");
      if (gatewayObjects.hasAdyen) detectedGateways.push("Adyen");
      if (gatewayObjects.hasSquare) detectedGateways.push("Square");

      // Flag official scripts/objects
      if (detectedGateways.length > 0) {
        signals.push({
          id: "payment_gateway_official",
          message: `✅ Official payment framework detected (${detectedGateways.join(", ")}). Critical data is handled via standardized APIs.`,
          weight: -15,
          category: "Sensitive Data",
        });
      } else if (
        officialElements.stripeElements > 0 || officialElements.paypalButtons > 0 ||
        officialElements.braintreeElements > 0 || officialElements.klarnaElements > 0 ||
        officialElements.adyenElements > 0 || officialElements.squareElements > 0 ||
        officialElements.amazonPayElements > 0 || officialElements.googlePayElements > 0
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
          message: `✅ Found structural elements belonging to a verified provider (${detectedElements.join(", ")}).`,
          weight: -10,
          category: "Sensitive Data",
        });
      }

      // Secure iframe nesting validation
      const paymentsInOfficialFrames = paymentInputs.filter((f) => isPaymentFieldInOfficialIframe(f)).length;
      if (paymentsInOfficialFrames > 0) {
        signals.push({
          id: "payment_fields_in_official_iframe",
          message: `✅ Verified isolation: ${paymentsInOfficialFrames} input field(s) are safely running within a sandboxed payment iframe.`,
          weight: -20,
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

      // --- MAGE CART & SKIMMER IMPERSONATION DETECTION ENGINE ---
      const unsafeFieldPresent = paymentInputs.some((input) => input.closest('iframe') === null);
      
      if (unsafeFieldPresent) {
        // ANOMALY 1: Raw inputs exist on the host DOM, but Stripe/PayPal tokens are present (Impersonation Skimmer)
        if (detectedGateways.length > 0 || officialElements.stripeElements > 0) {
          signals.push({
            id: "magecart_impersonation_skimmer",
            message: "🚨 CRITICAL SECURITY RISK: This site asks for raw card details while simulating a Stripe/PayPal interface. High probability of a digital credit card skimmer (Magecart)!",
            weight: 100,
            category: "Website Security"
          });
        } 
        // ANOMALY 2: Raw inputs exist and no trustworthy payment gateways are present anywhere on the page
        else if (detectedGateways.length === 0 && officialElements.stripeElements === 0 && officialElements.paypalButtons === 0 && officialElements.braintreeElements === 0) {
          signals.push({
            id: "unsafe_card_fields",
            message: "🚨 Warning: Card inputs are exposed directly on the parent page rather than an isolated secure portal. Risk of unencrypted data interception or leakage.",
            weight: 90,
            category: "Sensitive Data",
          });
        }
      }

      // Form Submit Destination Verification
      const trustedPaymentHosts = [
        "stripe.com", "api.stripe.com", "checkout.stripe.com", "js.stripe.com",
        "paypal.com", "www.paypal.com", "checkout.paypal.com",
        "braintreepayments.com", "client.braintreegateway.com",
        "klarna.com", "klarna-payments.com", "checkout.klarna.com",
        "adyen.com", "checkout.adyen.com", "checkoutshopper-live.adyen.com",
        "squareup.com", "web.squarecdn.com", "web-payments-sdk.squareup.com",
        "mollie.com", "mollie.nl", "checkout.mollie.com",
        "2checkout.com", "verifone.com", "payment.verifone.com",
        "authorize.net", "accept.authorize.net", "frauddetection.authorize.net",
        "mws.amazonservices.com", "amazon-pay.amazon.com", "amazon-payments",
        "apple.com", "google.com", "pay.google.com",
        "worldpay.com", "checkout.worldpay.com", "globalcollect.com", "ingenico.com",
        "threeds.io", "sagepay.com", "checkout.sagepay.com", "wise.com", "payoneer.com", "skrill.com"
      ];

      const isTrustedOrigin = (origin: string) => {
        try {
          const parsed = new URL(origin);
          return trustedPaymentHosts.some(
            (trusted) => parsed.hostname === trusted || parsed.hostname.endsWith(`.${trusted}`),
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
              message: "Critical hazard: This checkout form routes your inputs to an untrusted external endpoint. Extreme leakage danger.",
              weight: 100,
              category: "Website Security",
            });
          } else if (actionUrl.origin !== pageOrigin) {
            signals.push({
              id: "payment_form_external_submit",
              message: "Cross-origin redirection: The checkout data will be transferred away from the host origin.",
              weight: 65,
              category: "Website Security",
            });
          }
        } catch { /* ignore malformed forms */ }
      });
    }
  } catch { /* ignore */ }

  // 6. Verification Scripts vs Obfuscated Injection Keywords
  try {
    const officialPaymentScriptKeywords = [
      "js.stripe.com", "stripe", "paypal", "braintree", "klarna", 
      "adyen", "square", "mollie", "authorize.net", "worldpay"
    ];
    const suspiciousScriptKeywords = [
      "crypto-js", "card-number", "jquery.payment", "securepay", 
      "woocommerce", "payment-form", "skimmer", "keylogger"
    ];

    const officialScripts = pageScripts.filter((script) => {
      if (!script.src) return false;
      const normalized = script.src.toLowerCase();
      return officialPaymentScriptKeywords.some((keyword) => normalized.includes(keyword));
    });

    if (officialScripts.length > 0) {
      signals.push({
        id: "official_payment_script",
        message: `✅ Verified assets: Loaded ${officialScripts.length} cryptographically managed gateway scripts.`,
        weight: -10,
        category: "Website Security",
      });
    }

    const suspiciousScripts = pageScripts.filter((script) => {
      if (!script.src) return false;
      const normalized = script.src.toLowerCase();
      if (officialPaymentScriptKeywords.some((keyword) => normalized.includes(keyword))) {
        return false;
      }
      return suspiciousScriptKeywords.some((keyword) => normalized.includes(keyword));
    });

    if (suspiciousScripts.length > 0) {
      signals.push({
        id: "suspicious_payment_script",
        message: `Warning: Page loads custom local scripts invoking payment keywords (${suspiciousScripts.length} found).`,
        weight: 45,
        category: "Website Reputation",
      });
    }
  } catch { /* ignore */ }

  // 7. Cross-Origin Embed Isolation
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
        message: `Embeds an accumulation of cross-origin iframes (${crossOriginFrames.length}). Hidden widgets could harvest background parameters.`,
        weight: crossOriginFrames.length >= 8 ? 18 : 10,
        category: "Tracking & Storage",
      });
    }
  } catch { /* ignore */ }

  return signals;
}

// import type { RiskSignal } from "./types";

// // Helper: Check for official payment gateway objects in the window
// function detectPaymentGatewayObjects(): { hasStripe: boolean; hasPayPal: boolean; hasBraintree: boolean; hasKlarna: boolean; hasAdyen: boolean; hasSquare: boolean } {
//   const win = typeof window !== "undefined" ? window : {};
//   return {
//     hasStripe: !!(win as any).Stripe || !!(win as any).StripeCheckout,
//     hasPayPal: !!(win as any).paypal || !!(win as any).PAYPAL,
//     hasBraintree: !!(win as any).braintree || !!(win as any).BraintreeSetupForm,
//     hasKlarna: !!(win as any).Klarna || !!(win as any).klarna,
//     hasAdyen: !!(win as any).AdyenCheckout || !!(win as any).adyenCheckout,
//     hasSquare: !!(win as any).SqPaymentForm || !!(win as any).sq,
//   };
// }

// // Helper: detect official payment form elements in the DOM (e.g. Stripe Elements, PayPal buttons, etc.)
// function detectOfficialPaymentElements(): {
//   stripeElements: number;
//   paypalButtons: number;
//   braintreeElements: number;
//   klarnaElements: number;
//   adyenElements: number;
//   squareElements: number;
//   amazonPayElements: number;
//   googlePayElements: number;
// } {
//   const doc = typeof document !== "undefined" ? document : null;
//   if (!doc) return { stripeElements: 0, paypalButtons: 0, braintreeElements: 0, klarnaElements: 0, adyenElements: 0, squareElements: 0, amazonPayElements: 0, googlePayElements: 0 };

//   return {
//     stripeElements: doc.querySelectorAll('[class*="StripeElement"], [data-stripe], [id*="card-element"], [id*="stripe"]').length,
//     paypalButtons: doc.querySelectorAll('[id*="paypal"], [data-paypal], button[data-funding-source]').length,
//     braintreeElements: doc.querySelectorAll('[data-braintree], [class*="braintree"], [id*="braintree"]').length,
//     klarnaElements: doc.querySelectorAll('[data-klarna], [class*="klarna"], [id*="klarna"]').length,
//     adyenElements: doc.querySelectorAll('[data-adyen], [class*="adyen"], [id*="adyen"]').length,
//     squareElements: doc.querySelectorAll('[data-sq], [class*="square"], [id*="sq-"]').length,
//     amazonPayElements: doc.querySelectorAll('[data-amazon-pay], [class*="amazon-pay"], [id*="amazon"]').length,
//     googlePayElements: doc.querySelectorAll('[data-google-pay], [class*="google-pay"], [id*="google-pay"]').length,
//   };
// }

// // Helper: check if a payment-related input field is inside an official payment processor's iframe (e.g. Stripe, PayPal) which would indicate a secure integration rather than a risky direct card data collection form.
// function isPaymentFieldInOfficialIframe(field: HTMLInputElement): boolean {
//   const iframe = field.closest("iframe");
//   if (!iframe) return false;

//   const src = iframe.getAttribute("src") || "";
//   const trustedFrameSources = [
//     // Stripe
//     "js.stripe.com",
//     "stripe.com",
//     // PayPal
//     "paypal.com",
//     "www.paypal.com",
//     // Braintree
//     "braintreepayments.com",
//     // Klarna
//     "klarna.com",
//     "klarna-payments.com",
//     // Adyen
//     "adyen.com",
//     "checkoutshopper-",
//     // Square
//     "squareup.com",
//     "web.squarecdn.com",
//     // Mollie
//     "mollie.com",
//     // 2Checkout
//     "2checkout.com",
//     "verifone.com",
//     // Amazon Pay
//     "amazon-pay-",
//     // Worldpay
//     "worldpay.com",
//     // Authorize.Net
//     "authorize.net",
//   ];

//   return trustedFrameSources.some((trusted) => src.includes(trusted));
// }

// export function analyzeDOM(): RiskSignal[] {
//   const signals: RiskSignal[] = [];

//   const passwordField = document.querySelector('input[type="password"]');

//   if (passwordField) {
//     signals.push({
//       id: "password_field",
//       message: "This page is asking for your password",
//       weight: 40,
//       category: "Sensitive Data"
//     });
//   }

//   // Cookies (readable via document.cookie; does not include HttpOnly cookies)
//   try {
//     const cookieStr = typeof document.cookie === "string" ? document.cookie : "";
//     const cookieCount = cookieStr ? cookieStr.split(";").filter(Boolean).length : 0;
//     if (cookieCount > 0) {
//       signals.push({
//         id: "site_cookies_present",
//         message: `This site has set ${cookieCount} readable cookie${cookieCount === 1 ? "" : "s"} in your browser`,
//         weight: cookieCount >= 8 ? 20 : 10,
//         category: "Tracking & Storage",
//       });
//     }
//   } catch {
//     // ignore
//   }

//   // Local/session storage (current state snapshot)
//   try {
//     const localCount = globalThis.localStorage ? globalThis.localStorage.length : 0;
//     if (localCount > 0) {
//       signals.push({
//         id: "site_localstorage_present",
//         message: `This site stored ${localCount} item${localCount === 1 ? "" : "s"} in localStorage`,
//         weight: localCount >= 20 ? 20 : 10,
//         category: "Tracking & Storage",
//       });
//     }

//     const sessionCount = globalThis.sessionStorage ? globalThis.sessionStorage.length : 0;
//     if (sessionCount > 0) {
//       signals.push({
//         id: "site_sessionstorage_present",
//         message: `This site stored ${sessionCount} item${sessionCount === 1 ? "" : "s"} in sessionStorage`,
//         weight: sessionCount >= 20 ? 12 : 6,
//         category: "Tracking & Storage",
//       });
//     }
//   } catch {
//     // ignore
//   }

//   // Third-party scripts (rough tracker/ads indicator)
//   let pageScripts: HTMLScriptElement[] = [];
//   try {
//     const currentHost = window.location.hostname;
//     pageScripts = Array.from(document.scripts);
//     const thirdParty = pageScripts.filter((s) => {
//       if (!s.src) return false;
//       try {
//         const u = new URL(s.src, window.location.href);
//         return !!u.hostname && u.hostname !== currentHost;
//       } catch {
//         return false;
//       }
//     });

//     if (thirdParty.length >= 10) {
//       signals.push({
//         id: "third_party_scripts_high",
//         message: `Loads many third-party scripts (${thirdParty.length}) which can increase tracking`,
//         weight: thirdParty.length >= 25 ? 25 : 12,
//         category: "Tracking & Storage",
//       });
//     }
//   } catch {
//     // ignore
//   }

//   // Detect payment-related forms and fields
//   try {
//     const candidateInputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
//     const paymentTerms = [
//       "card",
//       "credit",
//       "cc-number",
//       "cc-csc",
//       "cc-cvv",
//       "security code",
//       "cvc",
//       "cvv",
//       "expiry",
//       "expiration",
//       "payment",
//       "billing",
//       "stripe",
//       "paypal",
//       "checkout",
//       "bank",
//     ];

//     function getInputContext(input: HTMLInputElement) {
//       const labels: string[] = [];
//       if (input.id) {
//         const label = document.querySelector(`label[for="${input.id}"]`);
//         if (label?.textContent) labels.push(label.textContent);
//       }
//       return [
//         input.name,
//         input.id,
//         input.placeholder,
//         input.getAttribute("aria-label"),
//         input.getAttribute("title"),
//         ...labels,
//       ]
//         .filter(Boolean)
//         .join(" ")
//         .toLowerCase();
//     }

//     const paymentInputs = candidateInputs.filter((input) => {
//       const context = getInputContext(input);
//       const autocomplete = (input.autocomplete || "").toLowerCase();
//       if (autocomplete.startsWith("cc-") || /cc-(name|number|exp|csc|cvv)/.test(autocomplete)) {
//         return true;
//       }
//       return paymentTerms.some((term) => context.includes(term));
//     });

//     if (paymentInputs.length > 0) {
//       signals.push({
//         id: "payment_data_entry",
//         message: `This page contains ${paymentInputs.length} field(s) that may collect credit card or payment data.`,
//         weight: 55,
//         category: "Sensitive Data",
//       });

//       // Check for official payment gateways
//       const gatewayObjects = detectPaymentGatewayObjects();
//       const officialElements = detectOfficialPaymentElements();

//       const detectedGateways: string[] = [];
//       if (gatewayObjects.hasStripe) detectedGateways.push("Stripe");
//       if (gatewayObjects.hasPayPal) detectedGateways.push("PayPal");
//       if (gatewayObjects.hasBraintree) detectedGateways.push("Braintree");
//       if (gatewayObjects.hasKlarna) detectedGateways.push("Klarna");
//       if (gatewayObjects.hasAdyen) detectedGateways.push("Adyen");
//       if (gatewayObjects.hasSquare) detectedGateways.push("Square");

//       if (detectedGateways.length > 0) {
//         signals.push({
//           id: "payment_gateway_official",
//           message: `✅ This page uses official payment processors (${detectedGateways.join(", ")}). Payment data is handled securely.`,
//           weight: -15, // NEGATIVE weight = reduces risk
//           category: "Sensitive Data",
//         });
//       } else if (
//         officialElements.stripeElements > 0 ||
//         officialElements.paypalButtons > 0 ||
//         officialElements.braintreeElements > 0 ||
//         officialElements.klarnaElements > 0 ||
//         officialElements.adyenElements > 0 ||
//         officialElements.squareElements > 0 ||
//         officialElements.amazonPayElements > 0 ||
//         officialElements.googlePayElements > 0
//       ) {
//         const detectedElements: string[] = [];
//         if (officialElements.stripeElements > 0) detectedElements.push("Stripe");
//         if (officialElements.paypalButtons > 0) detectedElements.push("PayPal");
//         if (officialElements.braintreeElements > 0) detectedElements.push("Braintree");
//         if (officialElements.klarnaElements > 0) detectedElements.push("Klarna");
//         if (officialElements.adyenElements > 0) detectedElements.push("Adyen");
//         if (officialElements.squareElements > 0) detectedElements.push("Square");
//         if (officialElements.amazonPayElements > 0) detectedElements.push("Amazon Pay");
//         if (officialElements.googlePayElements > 0) detectedElements.push("Google Pay");

//         signals.push({
//           id: "payment_elements_official",
//           message: `✅ Detected official payment form elements (${detectedElements.join(", ")} integration).`,
//           weight: -10,
//           category: "Sensitive Data",
//         });
//       }

//       // check if payment fields are inside official iframes (e.g. Stripe Elements) which would indicate a secure integration rather than a risky direct card data collection form
//       const paymentsInOfficialFrames = paymentInputs.filter((f) => isPaymentFieldInOfficialIframe(f)).length;
//       if (paymentsInOfficialFrames > 0) {
//         signals.push({
//           id: "payment_fields_in_official_iframe",
//           message: `✅ ${paymentsInOfficialFrames} payment field(s) are securely embedded in an official payment processor's iframe.`,
//           weight: -20, // NEGATIVE = safe
//           category: "Sensitive Data",
//         });
//       }

//       const paymentForms = Array.from(
//         new Set(
//           paymentInputs
//             .map((input) => input.closest("form"))
//             .filter((form): form is HTMLFormElement => !!form),
//         ),
//       );

//       const unsafeFieldPresent = paymentInputs.some((input) => input.closest('iframe') === null);
//       // Only flag as unsafe if there are payment fields AND no official gateway detected
//       if (unsafeFieldPresent && detectedGateways.length === 0 && officialElements.stripeElements === 0 && officialElements.paypalButtons === 0 && officialElements.braintreeElements === 0) {
//         signals.push({
//           id: "unsafe_card_fields",
//           message:
//             "🚨 Warning: The credit card fields are embedded directly into the website instead of being handled through a secure module (Stripe/PayPal). Risk of card skimming!",
//           weight: 90,
//           category: "Sensitive Data",
//         });
//       }

//       const trustedPaymentHosts = [
//         // Stripe
//         "stripe.com",
//         "api.stripe.com",
//         "checkout.stripe.com",
//         "js.stripe.com",
//         // PayPal
//         "paypal.com",
//         "www.paypal.com",
//         "checkout.paypal.com",
//         // Braintree (PayPal subsidiary)
//         "braintreepayments.com",
//         "client.braintreegateway.com",
//         // Klarna
//         "klarna.com",
//         "klarna-payments.com",
//         "checkout.klarna.com",
//         // Adyen
//         "adyen.com",
//         "checkout.adyen.com",
//         "checkoutshopper-live.adyen.com",
//         // Square
//         "squareup.com",
//         "web.squarecdn.com",
//         "web-payments-sdk.squareup.com",
//         // Mollie
//         "mollie.com",
//         "mollie.nl",
//         "checkout.mollie.com",
//         // 2Checkout / Verifone
//         "2checkout.com",
//         "verifone.com",
//         "payment.verifone.com",
//         // Authorize.Net
//         "authorize.net",
//         "accept.authorize.net",
//         "frauddetection.authorize.net",
//         // Amazon Pay
//         "mws.amazonservices.com",
//         "amazon-pay.amazon.com",
//         "amazon-payments",
//         // Apple Pay / Google Pay
//         "apple.com",
//         "google.com",
//         "pay.google.com",
//         // Worldpay / FIS
//         "worldpay.com",
//         "checkout.worldpay.com",
//         // Global Collect / Ingenico
//         "globalcollect.com",
//         "ingenico.com",
//         // 3D Secure
//         "threeds.io",
//         // SagePay
//         "sagepay.com",
//         "checkout.sagepay.com",
//         // Wise (formerly TransferWise)
//         "wise.com",
//         // Mollie
//         "mollie.com",
//         // Payoneer
//         "payoneer.com",
//         // Skrill
//         "skrill.com",
//       ];

//       const isTrustedOrigin = (origin: string) => {
//         try {
//           const parsed = new URL(origin);
//           return trustedPaymentHosts.some(
//             (trusted) =>
//               parsed.hostname === trusted || parsed.hostname.endsWith(`.${trusted}`),
//           );
//         } catch {
//           return false;
//         }
//       };

//       const pageOrigin = window.location.origin;
//       paymentForms.forEach((form) => {
//         const action = form.action || window.location.href;
//         try {
//           const actionUrl = new URL(action, window.location.href);
//           if (actionUrl.origin !== pageOrigin && !isTrustedOrigin(actionUrl.origin)) {
//             signals.push({
//               id: "payment_form_external_unknown_destination",
//               message:
//                 "This payment form submits sensitive data to an unfamiliar external origin, which greatly increases the risk of card data exfiltration.",
//               weight: 100,
//               category: "Website Security",
//             });
//           } else if (actionUrl.origin !== pageOrigin) {
//             signals.push({
//               id: "payment_form_external_submit",
//               message:
//                 "A payment form on this page submits to a different site, which can increase the risk of data misuse.",
//               weight: 65,
//               category: "Website Security",
//             });
//           }
//         } catch {
//           // ignore malformed form action
//         }
//       });
//     }
//   } catch {
//     // ignore
//   }

//   // Detect official payment-related scripts (NOT suspicious!)
//   try {
//     const officialPaymentScriptKeywords = [
//       "js.stripe.com",
//       "stripe",
//       "paypal",
//       "braintree",
//       "klarna",
//       "adyen",
//       "square",
//       "mollie",
//       "authorize.net",
//       "worldpay",
//     ];
//     const suspiciousScriptKeywords = [
//       "crypto-js",
//       "card-number",
//       "jquery.payment",
//       "securepay",
//       "woocommerce",
//       "payment-form",
//       "skimmer",
//       "keylogger",
//     ];

//     let officialPaymentScripts = 0;
//     const officialScripts = pageScripts.filter((script) => {
//       if (!script.src) return false;
//       const normalized = script.src.toLowerCase();
//       return officialPaymentScriptKeywords.some((keyword) => normalized.includes(keyword));
//     });
//     officialPaymentScripts = officialScripts.length;

//     if (officialPaymentScripts > 0) {
//       signals.push({
//         id: "official_payment_script",
//         message: `✅ Loaded ${officialPaymentScripts} official payment processor script(s) on the page.`,
//         weight: -10, // NEGATIVE = reduces risk
//         category: "Website Security",
//       });
//     }

//     const suspiciousScripts = pageScripts.filter((script) => {
//       if (!script.src) return false;
//       const normalized = script.src.toLowerCase();
//       // Don't flag official payment scripts as suspicious
//       if (officialPaymentScriptKeywords.some((keyword) => normalized.includes(keyword))) {
//         return false;
//       }
//       return suspiciousScriptKeywords.some((keyword) => normalized.includes(keyword));
//     });

//     if (suspiciousScripts.length > 0) {
//       signals.push({
//         id: "suspicious_payment_script",
//         message: `Loaded ${suspiciousScripts.length} suspicious payment-related script(s) on the page.`,
//         weight: 45,
//         category: "Website Reputation",
//       });
//     }
//   } catch {
//     // ignore
//   }

//   // Cross-site iframes (ads, widgets, trackers)
//   try {
//     const currentHost = window.location.hostname;
//     const frames = Array.from(document.querySelectorAll("iframe[src]"));
//     const crossOriginFrames = frames.filter((f) => {
//       const src = f.getAttribute("src");
//       if (!src) return false;
//       try {
//         const u = new URL(src, window.location.href);
//         return !!u.hostname && u.hostname !== currentHost;
//       } catch {
//         return false;
//       }
//     });
//     if (crossOriginFrames.length >= 3) {
//       signals.push({
//         id: "third_party_iframes",
//         message: `Embeds ${crossOriginFrames.length} third-party iframe${crossOriginFrames.length === 1 ? "" : "s"} (ads/widgets can track)`,
//         weight: crossOriginFrames.length >= 8 ? 18 : 10,
//         category: "Tracking & Storage",
//       });
//     }
//   } catch {
//     // ignore
//   }

//   return signals;
// }
