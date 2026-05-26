import { useState, useEffect } from "react";
import type { RiskSignal, InjectedSignal } from "../engine/types";
import { QUIZ_QUESTIONS, BADGE_DEFINITIONS } from "../engine/learningEngine";
import { getEducationalContent, getSeverityColor, getSeverityBg } from "../utils/educationalContent";
import { extensionApi } from "../utils/extensionApi";

type ExtensionSummaryItem = {
  id: string;
  name: string;
  enabled: boolean;
  hasActivity: boolean;
  riskScore: number;
  lastUsed?: number;
  isFromWebStore?: boolean;
};

type SitePermissionItem = {
  origin: string;
  permissions: string[];
};

type DashboardData = {
  extensionSummary: ExtensionSummaryItem[];
  sitePermissions: SitePermissionItem[];
};

type ExtensionActivityItem = {
  type: "extension_injection" | "network_request" | "data_access" | (string & {});
  detail: string;
};

const TRUSTED_EXTENSION_ID_ALLOWLIST = new Set<string>([
  // React Developer Tools (Chrome Web Store)
  'fmkadmapgofadopljbjfkapdkoienihi',
  // Angular DevTools (Chrome Web Store)
  'ienfalfjdbdpebioblfackkekamfmbnh',
  // uBlock Origin
  'cjpalhdlnbpafiamejdnhcphjbkeiagm',
  // AdBlock
  'gighmmpiobklfepjocnamgkkbiglidom',
  // LastPass
  'hdokiejnpimakedhajhdlcegeplioahd',
]);

const GITHUB_REPO_URL = 'https://github.com/JuliaFS/permission-guardian'; //TO DO change privacy
const SUPPORT_DEVELOPMENT_URL = 'https://github.com/sponsors/JuliaFS'; //TO DO add later

const TRUSTED_EXTENSION_NAME_KEYWORDS = [
  'react developer tools',
  'angular devtools',
  'ublock',
  'adblock',
  'lastpass',
];

function isSensitiveHostname(hostname: string) {
  const h = hostname.toLowerCase();
  return (
    h.includes('bank') ||
    h.includes('paypal') ||
    h.includes('login') ||
    h.includes('account') ||
    h.endsWith('.gov') ||
    h.endsWith('.mil')
  );
}

type Education = {
  title: string;
  why: string[];
  safer: string[];
};

const EDUCATION_BY_SIGNAL_ID: Record<string, Education> = {
  ext_host_all_urls: {
    title: "Runs on every website",
    why: [
      "This extension can work on every page you open in your browser.",
      "That means it sees all sites, including your bank, email, and private accounts.",
      "If the extension has a bug or becomes unsafe, it could affect everything you do online.",
    ],
    safer: [
      "Use extensions that only run on sites you choose.",
      "Only keep extensions with this access if you really trust them.",
    ],
  },
  ext_background_service_worker: {
    title: "Background code runs even when the page is closed",
    why: [
      "This extension can keep working quietly in the background.",
      "That means it can act without you opening a page first.",
      "If it does too much, it may collect data or do things you did not expect.",
    ],
    safer: [
      "Only use extensions with background code if you understand why they need it.",
      "Remove extensions you don’t use often.",
    ],
  },
  ext_background_persistent: {
    title: "Persistent background page",
    why: [
      "A persistent background page stays alive longer, which increases always-on tracking potential.",
      "It increases the impact of compromise because code is effectively always running.",
    ],
    safer: [
      "Prefer MV3-style service workers when possible, and avoid persistent background unless necessary.",
      "If you don’t need the extension daily, disable it.",
    ],
  },
  ext_perm_tabs: {
    title: "Permission: tabs",
    why: [
      "Can access tab URLs/titles and sometimes more detailed tab metadata depending on context.",
      "This can reveal what you browse, including sensitive pages.",
    ],
    safer: ["Prefer extensions that work with activeTab only, or are scoped to specific sites."],
  },
  ext_perm_cookies: {
    title: "Permission: cookies",
    why: [
      "Cookies can include session identifiers; stealing them can allow account takeover (session hijacking).",
      "Cookie access also enables tracking across sites.",
    ],
    safer: ["Avoid cookie access unless the extension’s core purpose requires it (e.g., cookie managers)."],
  },
  ext_perm_webRequest: {
    title: "Permission: webRequest",
    why: [
      "Can observe (and in some cases modify) network traffic, which may expose what you do online.",
      "Can be abused to inject, redirect, or fingerprint your browsing.",
    ],
    safer: ["Only trust this permission for well-known blockers/security tools with clear purpose."],
  },
  ext_perm_history: {
    title: "Permission: history",
    why: [
      "The extension can see the websites you have visited before.",
      "This can reveal your interests, work, and personal life.",
    ],
    safer: ["Only allow this if the extension clearly needs it for its task."],
  },
  ext_perm_activeTab: {
    title: "Access to the active tab (only after you click the extension)",
    why: [
      "When you click the extension, it gets temporary permission to read or modify the page you’re currently viewing.",
      "That means if you click it on a bank, email, or shopping page, it could see page content (and potentially change it).",
      "This permission is lower risk than “runs on all sites”, but it’s still powerful if misused.",
    ],
    safer: [
      "Only click the extension on pages you trust.",
      "If you don’t need it, don’t click it on sensitive pages (banking, payments, work tools).",
    ],
  },
  ext_perm_clipboardRead: {
    title: "Permission: clipboardRead",
    why: [
      "Clipboard often contains passwords, 2FA codes, crypto addresses, and private text.",
      "Attackers can read clipboard silently after certain user interactions.",
    ],
    safer: ["Avoid this permission unless you fully trust the extension and need clipboard features."],
  },
  ext_perm_clipboardWrite: {
    title: "Permission: clipboardWrite",
    why: [
      "Can replace what you copy (e.g., a payment address or a link) without obvious warning.",
      "This is a common tactic in crypto/payment malware.",
    ],
    safer: ["Double-check pasted content on sensitive actions (payments, logins, recovery codes)."],
  },
  ext_perm_scripting: {
    title: "Can run extra code on pages",
    why: [
      "This extension can add its own code to the page you visit.",
      "That means it could read what you type, click, or see on the page.",
    ],
    safer: [
      "Only allow scripting for extensions you trust completely.",
      "Avoid giving this permission to unknown extensions.",
    ],
  },
  password_field: {
    title: "Password input detected",
    why: [
      "Phishing pages often look identical to real login pages but send your password to attackers.",
      "Even on legitimate sites, passwords can be stolen by malicious scripts, compromised extensions, or insecure connections.",
    ],
    safer: [
      "Double‑check the domain (not just the page design).",
      "Prefer password managers (they match on the real domain).",
      "If unsure, open the site by typing it yourself instead of clicking the link.",
    ],
  },
  url_at_symbol: {
    title: "URL contains “@”",
    why: [
      "In URLs, text before “@” can be used to mislead you about the real destination.",
      "Attackers use this to show a trustworthy-looking prefix while the real host is after “@”.",
    ],
    safer: [
      "Look at the actual domain after “@” (and before the first “/”).",
      "When in doubt, don’t log in—navigate to the site manually.",
    ],
  },
  url_length: {
    title: "Unusually long URL",
    why: [
      "Very long URLs can hide the real domain or include tracking/redirect parameters.",
      "Phishing links often add extra path/query text to look “official” or to bypass filters.",
    ],
    safer: [
      "Focus on the domain first; ignore the long path/query.",
      "If it’s a login or payment page, open the site from bookmarks or typing the address.",
    ],
  },
  ip_address: {
    title: "Uses an IP address instead of a domain",
    why: [
      "Legitimate services usually use domain names; raw IPs are more common for malicious or temporary hosting.",
      "Certificates and brand signals are harder to verify when a site is addressed by IP.",
    ],
    safer: [
      "Avoid entering credentials on IP-based URLs.",
      "If you expect a real service, search for its official domain and compare.",
    ],
  },
  website_http_connection: {
    title: "Connection is not secure (HTTP)",
    why: [
      "HTTP connections send data in plain text, making it vulnerable to eavesdropping and tampering.",
      "Sensitive information (passwords, credit card numbers) can be intercepted by attackers.",
    ],
    safer: [
      "Avoid entering any sensitive information on HTTP sites.",
      "Look for 'HTTPS' in the URL and a padlock icon in your browser's address bar.",
    ],
  },
  website_new_domain: {
    title: "This domain appears to be very new or recently registered",
    why: [
      "Many phishing and scam sites use newly registered domains to avoid detection.",
      "New domains lack established reputation, making them inherently riskier.",
    ],
    safer: [
      "Exercise extreme caution. Verify the site's legitimacy through other trusted sources.",
      "Avoid logging in or sharing personal data unless you are absolutely certain of its authenticity.",
    ],
  },
  website_typosquatting: {
    title: "This site may be impersonating a popular service",
    why: [
      "Typosquatting (or URL hijacking) uses slight variations of popular domain names to trick users.",
      "Attackers aim to steal credentials or spread malware by mimicking trusted brands.",
    ],
    safer: [
      "Carefully check the URL for any misspellings, swapped characters, or unusual characters.",
      "Always type sensitive URLs directly or use bookmarks instead of clicking suspicious links.",
    ],
  },
  website_phishing_list: {
    title: "This site is on a known phishing list",
    why: [
      "This site has been identified by security services as hosting phishing content or malware.",
      "Visiting this site can lead to account compromise, data theft, or malware infection.",
    ],
    safer: ["Do NOT proceed to this site. Close the tab immediately.", "Report the site if possible."],
  },
  perm_camera_mic: {
    title: "Suspicious Camera + Microphone combo",
    why: [
      "Requesting both simultaneously is a common pattern for eavesdropping or unauthorized recording.",
      "Unknown domains asking for these together carry higher risk of privacy invasion.",
    ],
    safer: [
      "Deny if you aren't about to start a video call.",
      "Check if the site's primary purpose justifies this level of hardware access.",
    ],
  },
  perm_location: {
    title: "Location tracking request",
    why: [
      "Your precise location can be used for physical tracking or building a detailed profile of your movements.",
    ],
    safer: ["Only allow for maps, local weather, or services where geography is essential."],
  },
  perm_clipboard: {
    title: "Clipboard access requested",
    why: [
      "Malicious sites can read sensitive data (passwords, keys) or replace content (wallet addresses) in your clipboard.",
    ],
    safer: ["Be wary of sites requesting clipboard access unless you specifically triggered a paste action."],
  },
  perm_notifications: {
    title: "Notification permission request",
    why: [
      "Often used by scam sites to deliver 'your computer is infected' fake alerts or spam directly to your desktop.",
    ],
    safer: ["Deny unless you explicitly want updates from a trusted news or messaging site."],
  },
  site_cookies_present: {
    title: "This site stores browser cookies",
    why: [
      "Cookies are common for login, preferences, and session handling.",
      "More cookies also mean more identifiers that can be used for tracking or profiling.",
    ],
    safer: [
      "If you don’t fully trust the site, clear its cookies after you finish.",
      "Use privacy settings or tracker controls for sites you visit frequently.",
    ],
  },
  site_localstorage_present: {
    title: "This site stores localStorage data",
    why: [
      "LocalStorage is used to keep settings and site state across visits.",
      "It is also a persistent storage channel that can carry tracking data if abused.",
    ],
    safer: ["Clear site storage if you don’t trust the site.", "Use privacy or anti-tracking extensions when needed."],
  },
  site_sessionstorage_present: {
    title: "This site stores sessionStorage data",
    why: [
      "SessionStorage keeps state for the current tab without persisting after close.",
      "That still expands the browser-side surface area for activity tracking.",
    ],
    safer: ["Close the tab to clear session storage.", "Avoid entering sensitive data on untrusted pages."],
  },
  third_party_scripts_high: {
    title: "Many third-party scripts are loaded",
    why: [
      "Rich sites often load external scripts for ads, analytics, and widgets.",
      "Each external script adds tracking and supply-chain surface area.",
    ],
    safer: ["Use a tracker blocker on unfamiliar pages.", "Be cautious with logins and payments when many external scripts are present."],
  },
  third_party_iframes: {
    title: "Third-party iframes embedded",
    why: [
      "Third-party iframes can be used for ads, widgets, and tracking pixels.",
      "They can also be abused to deliver malicious content.",
    ],
    safer: ["Use a tracker blocker.", "Avoid interacting with suspicious embedded content."],
  },
  url_punycode: {
    title: "Domain uses punycode (possible look‑alike)",
    why: [
      "Internationalized domains can use characters that look like trusted brands.",
      "This is a common technique in phishing links.",
    ],
    safer: ["Double-check the domain carefully.", "Prefer navigating via bookmarks or typing the site manually."],
  },
  url_redirect_param: {
    title: "Link contains a redirect parameter",
    why: [
      "Redirect parameters can be used to send you to a different site than you expect.",
      "They are commonly abused in phishing and fake login flows.",
    ],
    safer: ["Check the final destination domain before logging in.", "If unsure, open the site directly instead of using the link."],
  },
};

function getEducation(signal: RiskSignal): Education {
  if (signal.id.endsWith("_mismatch")) {
    return {
      title: "Permission-purpose mismatch",
      why: [
        "If a permission doesn’t match the extension’s stated purpose, it could indicate overreach.",
        "Overbroad permissions increase the impact if the extension is compromised.",
      ],
      safer: [
        "Ask: could the extension work with fewer permissions?",
        "If you can’t justify it, avoid installing or keep it disabled until needed.",
      ],
    };
  }

  return (
    EDUCATION_BY_SIGNAL_ID[signal.id] ?? {
      title: signal.message,
      why: [
        "This is a warning about something the extension thinks is risky.",
        "It may not be dangerous by itself, but it is worth paying attention to.",
      ],
      safer: [
        "If you do not understand why this is happening, close the page or leave the site.",
        "Only share personal information on sites you trust.",
      ],
    }
  );
}

function getRiskCategory(score: number) {
  if (score <= 10) return { label: 'Low Risk', color: '#059669' };
  if (score <= 40) return { label: 'Medium Risk', color: '#d86f1e' };
  return { label: 'High Risk', color: '#dc2626' };
}

function formatActivity(
  type: ExtensionActivityItem['type'],
  detail: string,
  options?: { resolveExtensionName?: (extensionId: string) => string | undefined; isWebStoreExtension?: (extensionId: string) => boolean },
): {
  key: string;
  label: string;
  message: string;
  details?: string;
  detailsButton?: { closed: string; open: string };
  tone?: 'safe' | 'info' | 'warning';
} {
  const describeKnownUrl = (url: URL): { label?: string; message?: string; details?: string; tone?: 'safe' | 'info' | 'warning' } | null => {
    const host = url.hostname.toLowerCase();
    const path = url.pathname || '/';

    // Inline/other non-URL script descriptor should be handled separately.
    if (url.protocol === 'data:') {
      return {
        label: '🎨 Data resource',
        message: 'This is an inline or data URI resource loaded by the page. It is often used for images, fonts, or embedded widgets.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    // Google Analytics / Tag Manager
    if (host.endsWith('googletagmanager.com') || path.includes('/gtm.js')) {
      return {
        label: '📊 Google Tag Manager',
        message:
          'This is Google Tag Manager or a related analytics loader. It is used to wire up analytics and marketing tags on the page.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    if (host.endsWith('google-analytics.com') || path.includes('/gtag/js') || path.includes('/analytics.js')) {
      return {
        label: '📊 Google Analytics',
        message: 'This is Google Analytics. It is used to collect usage and visitor data for the site.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    if (host.endsWith('js.stripe.com') || host.includes('stripe.com')) {
      return {
        label: '💳 Stripe payment script',
        message: 'This is a Stripe payment script. It is used to handle checkout and payment forms.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    if (host.includes('paypal.com') || host.includes('paypalobjects.com')) {
      return {
        label: '💳 PayPal payment script',
        message: 'This is a PayPal payment script. It is used for PayPal checkout and payment branding.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    if (host.includes('facebook.net') || host.includes('facebook.com') || host.includes('connect.facebook.net')) {
      return {
        label: '📊 Facebook Pixel / SDK',
        message:
          'This is Facebook tracking or SDK code. It is often used for ads, analytics, and conversion tracking.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    if (host.includes('doubleclick.net') || host.includes('adsrvr.org') || host.includes('adservice.google.com')) {
      return {
        label: '📢 Ad/tracking script',
        message: 'This is an advertising or tracking script. It is commonly used to measure and serve ads.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    if (host.includes('segment.com') || host.includes('amplitude.com') || host.includes('mixpanel.com')) {
      return {
        label: '📊 Analytics script',
        message: 'This is a third-party analytics provider used to collect usage and behavior data.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    // Vercel Web Analytics / Insights
    if (path.startsWith('/_vercel/insights/') || host.includes('vercel-insights')) {
      return {
        label: '📊 Analytics script (Vercel)',
        message:
          'This is Vercel Web Analytics (Insights). Many sites include it to measure performance and usage. It is usually normal, but it can look suspicious if you weren’t expecting analytics.',
        details: `${host}${path}`,
        tone: 'info',
      };
    }

    // Google CDN / app resources
    if (host.endsWith('gstatic.com')) {
      if (path.includes('/external_hosted/highlights/') || path.endsWith('highlight.pack.js')) {
        return {
          label: '💡 Syntax highlighter',
          message:
            'This is a code syntax-highlighting library loaded from Google’s CDN (gstatic). It’s commonly used on pages that display code.',
          details: `${host}${path}`,
          tone: 'safe',
        };
      }

      if (host === 'gemini.gstatic.com' || path.startsWith('/_/js/')) {
        return {
          label: '✅ App resources (Google)',
          message:
            'These are Google app resources (scripts/assets) loaded for the page to work. This is normal on Google-owned sites.',
          details: `${host}${path}`,
          tone: 'safe',
        };
      }
    }

    return null;
  };

  const describeInlineScript = (detail: string): { label: string; message: string; tone: 'safe' | 'info' | 'warning' } | null => {
    if (!detail.startsWith('Inline script')) return null;

    const match = detail.match(/^Inline script(?: \((.+)\))?$/i);
    const kind = match?.[1]?.toLowerCase() ?? '';

    if (kind.includes('analytics')) {
      return {
        label: '📊 Inline analytics script',
        message: 'This page injected an inline analytics script. This is often used to measure usage or conversions.',
        tone: 'info',
      };
    }
    if (kind.includes('tag manager')) {
      return {
        label: '📦 Inline tag manager script',
        message: 'This is an inline tag manager script. It is used to wire up analytics and marketing tags.',
        tone: 'info',
      };
    }
    if (kind.includes('facebook pixel')) {
      return {
        label: '📊 Inline Facebook Pixel',
        message: 'This is an inline Facebook Pixel script. It is used for ads and conversion tracking.',
        tone: 'info',
      };
    }
    if (kind.includes('payment')) {
      return {
        label: '💳 Inline payment script',
        message: 'This is an inline payment-related script. It may be part of a checkout or payment form.',
        tone: 'info',
      };
    }
    if (kind.includes('tracking')) {
      return {
        label: '🔍 Inline tracking script',
        message: 'This is an inline tracking script. It may collect analytics or fingerprinting data.',
        tone: 'info',
      };
    }
    if (kind.includes('captcha')) {
      return {
        label: '🧾 Inline CAPTCHA script',
        message: 'This is an inline CAPTCHA script. It is usually used to verify human users.',
        tone: 'info',
      };
    }
    if (kind.includes('media embed')) {
      return {
        label: '🎬 Inline media/script embed',
        message: 'This is an inline script related to embedded media or playback.',
        tone: 'info',
      };
    }

    return {
      label: '🧩 Inline script',
      message: 'This page injected an inline script. Inline scripts can be used for page behavior, analytics, or hidden tracking.',
      tone: 'info',
    };
  };

  const inlineScript = describeInlineScript(detail);
  if (inlineScript) {
    return {
      key: `${type}:${detail}`,
      label: inlineScript.label,
      message: inlineScript.message,
      tone: inlineScript.tone,
    };
  }

  const fallback = {
    key: `${type}:${detail}`,
    label:
      type === 'extension_injection'
        ? '💉 Script Injected'
        : type === 'network_request'
          ? '🌐 Network Request'
          : type === 'dynamic_injection'
            ? '🧩 Page changed'
            : '🍪 Site Data Access',
    message: detail,
  };

  let url: URL | null = null;
  try {
    url = new URL(detail);
  } catch {
    return fallback;
  }

  const known = describeKnownUrl(url);
  if (known) {
    return {
      key: `${type}:${url.hostname}${url.pathname}`,
      label: known.label ?? fallback.label,
      message: known.message ?? fallback.message,
      details: known.details,
      detailsButton: known.details ? { closed: '💡 Learn more', open: 'Hide details' } : undefined,
      tone: known.tone ?? 'info',
    };
  }

  const host = url.hostname;
  const path = url.pathname || '/';
  const isScript = path.endsWith('.js');
  const isChromeExtension = url.protocol === 'chrome-extension:';
  const isJobsBgStats = host === 'stats2.jobs.bg' && path.startsWith('/add/');
  const pageHost = (() => {
    try {
      return globalThis.location?.hostname ? globalThis.location.hostname.toLowerCase() : '';
    } catch {
      return '';
    }
  })();

  const isSameSite = (() => {
    if (!pageHost) return false;
    const a = host.toLowerCase();
    const b = pageHost.toLowerCase();
    return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
  })();

  const lastPathSegment = (p: string) => {
    const cleaned = p.split('?')[0];
    const parts = cleaned.split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1] : cleaned || '/';
  };

  if (type === 'extension_injection' || isChromeExtension) {
    const extensionId = host;
    const file = lastPathSegment(path);
    const extensionName = options?.resolveExtensionName?.(extensionId);
    const isWebStoreExtension = options?.isWebStoreExtension?.(extensionId) ?? false;

    const normalizedName = (extensionName || '').toLowerCase();
    const isTrusted =
      TRUSTED_EXTENSION_ID_ALLOWLIST.has(extensionId) ||
      isWebStoreExtension ||
      TRUSTED_EXTENSION_NAME_KEYWORDS.some((k) => normalizedName.includes(k));

    const isSensitivePage = pageHost ? isSensitiveHostname(pageHost) : false;

    return {
      key: `extension_injection:${extensionId}:${file}`,
      label: isTrusted
        ? '✅ Trusted tool'
        : isSensitivePage
          ? '🚨 Unknown extension on a sensitive site'
          : '🧩 Extension changed the page',
      message: isTrusted
        ? `The tool “${extensionName || extensionId}” is checking/enhancing this page. This is normal for that extension.`
        : isSensitivePage
          ? `An unknown extension is running on a sensitive page (banking/login). If you don’t recognize it, disable or remove it.`
          : extensionName
            ? `The extension “${extensionName}” added code to this page so its features can work.`
            : `A browser extension added code to this page so its features can work.`,
      details: extensionName
        ? `Extension: ${extensionName} (ID: ${extensionId}), file: ${file}`
        : `Extension ID: ${extensionId}, file: ${file}`,
      detailsButton: { closed: '💡 Learn more', open: 'Hide details' },
      tone: isTrusted ? 'safe' : isSensitivePage ? 'warning' : 'info',
    };
  }

  if (type === 'dynamic_injection') {
    const isIframe = detail.includes('.html') || detail.includes('/embed') || detail.includes('iframe');
    const extension = path.split('?')[0].split('.').pop()?.toLowerCase() ?? '';
    const isStylesheet = extension === 'css';
    const isImage = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg'].includes(extension);
    const isVideo = ['mp4', 'webm', 'ogg', 'mov', 'avi'].includes(extension);
    const isFont = ['woff', 'woff2', 'ttf', 'otf', 'eot'].includes(extension);
    const isDataUri = detail.startsWith('data:');

    const label = isScript
      ? '🧩 Script added to page'
      : isStylesheet
        ? '🎨 Stylesheet added'
        : isImage
          ? '🖼️ Image added'
          : isVideo
            ? '🎬 Video added'
            : isFont
              ? '🔤 Font added'
              : isIframe
                ? '🧩 Embedded content added'
                : '🧩 Page added a resource';

    const message = isScript
      ? `This page dynamically added a script from ${host}. This is often normal (analytics/widgets), but unexpected third-party scripts can increase tracking risk.`
      : isStylesheet
        ? `This page dynamically added a stylesheet from ${host}. This is often normal, but third-party styles can also be used for tracking or cosmetic manipulation.`
        : isImage
          ? `This page dynamically added an image from ${host}. This is usually normal, but third-party media can still affect privacy and page behavior.`
          : isVideo
            ? `This page dynamically added a video from ${host}. This is usually normal for media-rich sites, but external media can expose user behavior to third parties.`
            : isFont
              ? `This page dynamically added a font from ${host}. This is usually normal for custom typography, but it still fetches external resources.`
              : isDataUri
                ? `This page dynamically added an inline data resource. This is often normal, but it can include embedded tracking or fingerprinting content.`
                : `This page dynamically added a resource from ${host}. This is often normal, but it can be used for tracking.`;

    return {
      key: `dynamic_injection:${host}${path}`,
      label,
      message,
      details: `${host}${path}`,
      detailsButton: { closed: '💡 Learn more', open: 'Hide details' },
      tone: isSameSite ? 'safe' : 'info',
    };
  }

  if (type === 'network_request' || type === 'data_access') {
    if (isJobsBgStats) {
      return {
        key: `tracking:${host}${path}`,
        label: type === 'network_request' ? '📊 Tracking request' : '📊 Tracking request',
        message: `A tracking/analytics request was sent to ${host}.`,
        details: `${host}${path}`,
        detailsButton: { closed: '💡 Learn more', open: 'Hide details' },
        tone: 'info',
      };
    }

    if (isScript) {
      const file = lastPathSegment(path);
      return {
        key: `script_load:${host}${path}`,
        label: isSameSite ? '✅ Normal page code' : '🧩 Third‑party code loaded',
        message: isSameSite
          ? `This website loaded its own script from ${host} (${file}). This is normal.`
          : `This page loaded a script from another site: ${host} (${file}). If you don’t recognize it, it could be analytics/ads/tracking.`,
        details: `${host}${path}`,
        detailsButton: { closed: '💡 Learn more', open: 'Hide details' },
        tone: isSameSite ? 'safe' : 'info',
      };
    }

    return {
      key: `request:${host}${path}`,
      label: type === 'network_request' ? '🌐 Website connection' : '🌐 Website connection',
      message: `This page connected to ${host}.`,
      details: `${host}${path}`,
      detailsButton: { closed: '💡 Learn more', open: 'Hide details' },
      tone: isSameSite ? 'safe' : 'info',
    };
  }

  return fallback;
}

export function WarningPanel({
  overall,
  page,
  extension,
  pageSignals,
  extensionSignals,
  behavior,
  extensionActivity,
  injectedSignals,
  onClose,
  showCloseButton,
}: {
  overall: { score: number; level: string };
  page: { score: number; level: string };
  extension: { score: number; level: string };
  pageSignals: RiskSignal[];
  extensionSignals: RiskSignal[];
  behavior?: {
    score: number | null;
    habits: string[];
    suggestions: string[];

  };
  extensionActivity?: ExtensionActivityItem[];
  injectedSignals?: InjectedSignal[];
  onClose: () => void;
  showCloseButton: boolean;
}) {
  const [view, setView] = useState<'signals' | 'dashboard' | 'learn'>('signals');
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [unlockedBadges, setUnlockedBadges] = useState<string[]>([]);
  const [quizIdx, setQuizIdx] = useState(0);
  const [quizFeedback, setQuizFeedback] = useState<string | null>(null);
  const [mode, setMode] = useState<'strict' | 'balanced' | 'silent'>('balanced');
  const [activityDetailsOpen, setActivityDetailsOpen] = useState<Record<string, boolean>>({});
  const [activeInfoTopic, setActiveInfoTopic] = useState<string | null>(null);

  const INFO_TOPICS: Record<string, { label: string; description: string }> = {
    thirdPartyScripts: {
      label: 'Third-party scripts',
      description:
        'Third-party scripts are loaded from domains other than the page you are visiting. Sites use them for ads, analytics, payment widgets, and social login. They can be useful, but untrusted third parties can also track you, inject extra code, or expose data if the site is compromised.',
    },
    cookies: {
      label: 'Cookies',
      description:
        'Cookies store small pieces of data such as login state, shopping cart contents, and site preferences. They are needed for normal browsing, but if a cookie is stolen an attacker can impersonate your session on that site.',
    },
    localStorage: {
      label: 'Local storage',
      description:
        'localStorage is browser storage that websites use to remember settings and cached data across visits. It is useful for faster page loading, but data stored here can become dangerous if a malicious script reads it without permission.',
    },
    sessionStorage: {
      label: 'Session storage',
      description:
        'sessionStorage keeps temporary data while a browser tab is open. It helps pages preserve state during one visit. It is normally safe, but if stolen it can still reveal sensitive session data or login state.',
    },
    privacySurface: {
      label: 'Privacy surface',
      description:
        'This page uses tracking/storage mechanisms like cookies, localStorage, sessionStorage, or third-party scripts. That is usually normal for modern web apps, but it also increases the amount of data that can be tracked or leaked if the page is compromised.',
    },
  };

  useEffect(() => {
    const fetchData = async () => {
      const response = await extensionApi.getDashboardData();
      if (response) {
        // Map the background response (extensions, history, activity) to the DashboardData structure
        const siteMap = new Map<string, Set<string>>();
        (response.history || []).forEach((item: any) => {
          if (!siteMap.has(item.origin)) siteMap.set(item.origin, new Set());
          siteMap.get(item.origin)?.add(item.permission);
        });

        setDashboardData({
          extensionSummary: (response.extensions || []).map((ext: any) => ({
            id: ext.id,
            name: ext.name,
            enabled: ext.enabled,
            riskScore: (ext.permissions?.length || 0) * 10,
            hasActivity: (response.activity || []).some((a: any) => a.extensionId === ext.id),
            lastUsed: response.lastUsed,
            isFromWebStore: ext.isFromWebStore ?? false
          })),
          sitePermissions: Array.from(siteMap.entries()).map(([origin, perms]) => ({
            origin,
            permissions: Array.from(perms)
          }))
        });
      }

      const result = await extensionApi.getStorage(['unlockedBadges', 'pg_mode']);
      let badges = result.unlockedBadges || ['guardian_initiate'];
      if (behavior && typeof behavior.score === 'number' && behavior.score > 90 && !badges.includes('privacy_pro')) {
        badges.push('privacy_pro');
      }
      setUnlockedBadges(badges);
      if (result.pg_mode) setMode(result.pg_mode);
    };

    fetchData();
  }, []);

  // Fix: Move the early return after all Hooks are defined to satisfy React Rules of Hooks
  if (!extensionApi.isAvailable) return null;

  const removeExtension = async (id: string) => {
    await extensionApi.removeExtension(id);
  };

  const revokeSite = async (origin: string) => {
    await extensionApi.clearSiteData(origin);
  };

  const changeMode = (m: 'strict' | 'balanced' | 'silent') => {
    setMode(m);
    extensionApi.setStorage({ pg_mode: m });
  };

  const handleQuizAnswer = (idx: number) => {
    const question = QUIZ_QUESTIONS[quizIdx];
    if (idx === question.correctIndex) {
      setQuizFeedback("✅ Correct! " + question.explanation);
      if (!unlockedBadges.includes('eagle_eye')) {
        const next = [...unlockedBadges, 'eagle_eye'];
        setUnlockedBadges(next);
        extensionApi.setStorage({ unlockedBadges: next });
      }
    } else {
      setQuizFeedback("❌ Incorrect. " + question.explanation);
    }
  };

  const getSuggestions = () => {
    const list: string[] = [];
    if (behavior?.suggestions) list.push(...behavior.suggestions);
    
    const unusedExts = dashboardData?.extensionSummary?.filter(e => !e.hasActivity && e.enabled).length || 0;
    if (unusedExts > 0) list.push(`Remove or disable ${unusedExts} unused extensions`);

    const heavySites = dashboardData?.sitePermissions?.filter(s => s.permissions.length > 2).length || 0;
    if (heavySites > 0) list.push(`Revoke excessive permissions from ${heavySites} sites`);

    return list;
  };

  // Normalize incoming scores and derive display categories
  const normOverallScore = Math.max(0, Math.min(100, Math.round((overall && typeof overall.score === 'number') ? overall.score : 0)));
  const normPageScore = Math.max(0, Math.min(100, Math.round((page && typeof page.score === 'number') ? page.score : 0)));
  const normExtensionScore = Math.max(0, Math.min(100, Math.round((extension && typeof extension.score === 'number') ? extension.score : 0)));
  const overallCat = getRiskCategory(normOverallScore);
  const pageCat = getRiskCategory(normPageScore);
  const extensionCat = getRiskCategory(normExtensionScore);

  const pageTopSignals = (pageSignals ?? [])
    .slice()
    .sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0))
    .slice(0, 3);
  const pageMaxWeight = (pageSignals ?? []).reduce((m, s) => Math.max(m, s.weight ?? 0), 0);
  // "Serious" should be rare and clearly justified (phishing-ish, insecure transport, password capture, etc.)
  // Keep mild privacy/tracking findings (cookies/storage/third-party scripts) in the yellow banner.
  const pageHasSeriousSignal = pageMaxWeight >= 50 || normPageScore >= 40;
  const pageHasAnySignal = (pageSignals ?? []).length > 0;
  const pageHasPrivacySurface = (pageSignals ?? []).some((s) =>
    s.category === "Tracking & Storage" &&
    [
      "site_cookies_present",
      "site_localstorage_present",
      "site_sessionstorage_present",
      "third_party_scripts_high",
      "third_party_iframes",
    ].includes(s.id),
  );

  const parseSignalCount = (signalId: string) => {
    const signal = (pageSignals ?? []).find((s) => s.id === signalId);
    if (!signal || typeof signal.message !== 'string') return 0;
    const match = signal.message.match(/(\d+)/);
    return match ? Number(match[1]) : 0;
  };

  const pageSummaryCounts = [
    { label: 'Cookies', count: parseSignalCount('site_cookies_present') },
    { label: 'LocalStorage', count: parseSignalCount('site_localstorage_present') },
    { label: 'SessionStorage', count: parseSignalCount('site_sessionstorage_present') },
    { label: '3rd-party scripts', count: parseSignalCount('third_party_scripts_high') },
    { label: '3rd-party iframes', count: parseSignalCount('third_party_iframes') },
  ].filter((item) => item.count > 0);

  const pageBanner = (() => {
    if (!pageHasAnySignal && normPageScore <= 10) return null;

    const items = pageTopSignals.map((s) => s.message).filter(Boolean);
    const highlights = items.length > 0 ? items.join(" · ") : "Some risky patterns were detected.";

    if (pageHasSeriousSignal) {
      return {
        tone: "danger" as const,
        title: "⚠️ This page may be harmful",
        body: `Reason: ${highlights}`,
      };
    }

    return {
      tone: "warning" as const,
      title: "⚠️ This page shows tracking or risky patterns",
      body: `What we noticed: ${highlights}`,
    };
  })();

  return (
    <div 
      className="guardian-panel"
      style={{
        backgroundColor: '#ffffff',
        borderRadius: '12px',
        boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb',
        padding: '20px',
        width: '100%',
        maxHeight: 'calc(95vh - 40px)',
        overflowY: 'auto',
        fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
        color: '#111827',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative' // Needed for absolute positioning of close button
      }}
    >
      {showCloseButton ? (
        <button
          type="button"
          className="guardian-panel__close"
          aria-label="Close Permission Guardian panel"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onClose();
          }}
          style={{
            position: 'absolute',
            top: '12px',
            right: '12px',
            background: 'none',
            border: 'none',
            fontSize: '24px',
            cursor: 'pointer',
            color: '#9ca3af',
            lineHeight: 1,
            padding: '4px'
          }}
        >
          ×
        </button>
      ) : null}
      <h3>🛡️ Permission Guardian</h3>

      <div className="guardian-panel__tabs" style={{ display: 'flex', gap: '4px', marginBottom: '16px' }}>
        <button 
          className={`guardian-panel__tab ${view === 'signals' ? 'active' : ''}`}
          onClick={(e) => { e.stopPropagation(); setView('signals'); }}
          style={{ flex: 1, padding: '4px', cursor: 'pointer', border: '1px solid #ddd', borderRadius: '4px', background: '#fff', color: '#111' }}
        >
          Live Analysis
        </button>
        <button 
          className={`guardian-panel__tab ${view === 'dashboard' ? 'active' : ''}`}
          onClick={(e) => { e.stopPropagation(); setView('dashboard'); }}
          style={{ flex: 1, padding: '4px', cursor: 'pointer', border: '1px solid #ddd', borderRadius: '4px', background: '#fff', color: '#111' }}
        >
          Dashboard
        </button>
        <button 
          className={`guardian-panel__tab ${view === 'learn' ? 'active' : ''}`}
          onClick={(e) => { e.stopPropagation(); setView('learn'); }}
          style={{ flex: 1, padding: '4px', cursor: 'pointer', border: '1px solid #ddd', borderRadius: '4px', background: '#fff', color: '#111' }}
        >
          Learn
        </button>
      </div>

      {/* Top summary: overall score and quick status */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '12px' }}>
        <div style={{ width: '100%', background: '#f8fafc', padding: '12px', borderRadius: '8px', border: '1px solid #eef2ff' }}>
          <div style={{ fontSize: '12px', color: '#6b7280' }}>Overall Risk</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '6px' }}>
            <div style={{ fontSize: '20px', fontWeight: '700', color: overallCat.color }}>
              {normOverallScore}/100
            </div>
            <div style={{ fontSize: '13px', color: '#111827' }}>
              <strong>{overallCat.label}</strong>
              <div style={{ fontSize: '12px', color: '#6b7280' }}>
                Page: <strong>{pageCat.label} ({normPageScore})</strong> · Extension: <strong>{extensionCat.label} ({normExtensionScore})</strong>
              </div>
              {pageSummaryCounts.length > 0 ? (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '8px' }}>
                  {pageSummaryCounts.map((item) => (
                    <div
                      key={item.label}
                      style={{
                        background: '#f8fafc',
                        border: '1px solid #dbeafe',
                        borderRadius: '999px',
                        padding: '4px 10px',
                        fontSize: '11px',
                        color: '#1e3a8a',
                        fontWeight: 600,
                      }}
                    >
                      {item.label}: {item.count}
                    </div>
                  ))}
                </div>
              ) : null}
              {pageHasPrivacySurface ? (
                <button
                  onClick={() => setActiveInfoTopic(activeInfoTopic === 'privacySurface' ? null : 'privacySurface')}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    marginTop: '6px',
                    fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, sans-serif',
                    fontSize: '11px',
                    lineHeight: 1.3,
                    color: '#475569',
                    background: '#eff6ff',
                    border: '1px solid #bfdbfe',
                    borderRadius: '999px',
                    padding: '6px 10px',
                    cursor: 'pointer',
                    fontWeight: 600,
                  }}
                >
                  <span style={{ color: '#1d4ed8' }}>Privacy surface</span>
                  <span style={{ fontWeight: 400 }}>Tap for details</span>
                </button>
              ) : null}
            </div>
          </div>
        </div>

        {/* Prominent page warning when relevant */}
        {pageBanner && (
          <div
            style={{
              width: '100%',
              background: pageBanner.tone === 'danger' ? '#fff7f7' : '#fffbeb',
              border: pageBanner.tone === 'danger' ? '1px solid #fee2e2' : '1px solid #fde68a',
              color: pageBanner.tone === 'danger' ? '#7f1d1d' : '#92400e',
              padding: '12px',
              borderRadius: '8px',
            }}
          >
            <div style={{ fontWeight: 700, marginBottom: '6px' }}>{pageBanner.title}</div>
            <div style={{ fontSize: '12px' }}>{pageBanner.body}</div>
          </div>
        )}

      <div style={{ marginTop: '12px', width: '100%' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
          {Object.entries(INFO_TOPICS).map(([key, topic]) => (
            <button
              key={key}
              onClick={() => setActiveInfoTopic(activeInfoTopic === key ? null : key)}
              style={{
                background: activeInfoTopic === key ? '#e5e7eb' : '#f8fafc',
                border: '1px solid #d1d5db',
                borderRadius: '999px',
                padding: '8px 12px',
                cursor: 'pointer',
                color: '#111827',
                fontSize: '12px',
                fontWeight: 600,
              }}
            >
              {topic.label}
            </button>
          ))}
        </div>
        {activeInfoTopic ? (
          <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '12px', fontSize: '12px', color: '#111827' }}>
            {INFO_TOPICS[activeInfoTopic].description}
          </div>
        ) : null}
      </div>
      </div>

      {view === 'learn' ? (
        <div className="guardian-panel__learn">
          <h4>🏆 Your Badges</h4>
          <div style={{ display: 'flex', gap: '10px', marginBottom: '20px', flexWrap: 'wrap' }}>
            {BADGE_DEFINITIONS.map(badge => (
              <div key={badge.id} style={{ 
                opacity: unlockedBadges.includes(badge.id) ? 1 : 0.3,
                textAlign: 'center', width: '60px'
              }} title={badge.description}>
                <div style={{ fontSize: '24px' }}>{badge.icon}</div>
                <div style={{ fontSize: '10px' }}>{badge.name}</div>
              </div>
            ))}
          </div>

          <h4>🧩 Quick Quiz</h4>
          <div style={{ background: '#f3f4f6', color: '#111', padding: '12px', borderRadius: '8px' }}>
            <p style={{ margin: '0 0 10px 0', fontSize: '13px', fontWeight: 'bold' }}>
              {QUIZ_QUESTIONS[quizIdx].text}
            </p>
            {QUIZ_QUESTIONS[quizIdx].options.map((opt, i) => (
              <button 
                key={i} 
                onClick={() => handleQuizAnswer(i)}
                style={{ 
                  display: 'block', width: '100%', textAlign: 'left', 
                  marginBottom: '5px', padding: '6px', fontSize: '12px',
                  cursor: 'pointer', borderRadius: '4px', border: '1px solid #ccc',
                  background: '#fff', color: '#111'
                }}
              >
                {opt}
              </button>
            ))}
            {quizFeedback && (
              <div style={{ fontSize: '11px', marginTop: '10px', fontStyle: 'italic', color: '#374151' }}>
                {quizFeedback}
                <button 
                  onClick={() => { setQuizIdx((quizIdx + 1) % QUIZ_QUESTIONS.length); setQuizFeedback(null); }}
                  style={{ display: 'block', marginTop: '5px', background: 'none', border: 'none', color: '#2563eb', cursor: 'pointer', padding: 0 }}
                >
                  Next Question →
                </button>
              </div>
            )}
          </div>
          
          <div style={{ marginTop: '15px', fontSize: '12px', color: '#9ca3af' }}>
            Tip: Always hover over links to see the real destination in the bottom corner of your browser.
          </div>
        </div>
      ) : view === 'dashboard' ? (
        <div className="guardian-panel__dashboard">
          <h4>🛡️ Protection Mode</h4>
          <div style={{ display: 'flex', gap: '4px', marginBottom: '16px' }}>
            {[
              { id: 'strict', label: '🛑 Strict', desc: 'Warn everything' },
              { id: 'balanced', label: '⚖️ Balanced', desc: 'Risky only' },
              { id: 'silent', label: '💤 Silent', desc: 'Logs only' }
            ].map(m => (
              <button
                key={m.id}
                onClick={() => changeMode(m.id as any)}
                style={{
                  flex: 1, padding: '6px 2px', fontSize: '11px', cursor: 'pointer',
                  border: '1px solid #ddd', borderRadius: '4px',
                  background: mode === m.id ? '#e5e7eb' : '#fff',
                  color: '#111',
                  fontWeight: mode === m.id ? 'bold' : 'normal'
                }}
                title={m.desc}
              >
                {m.label}
              </button>
            ))}
          </div>

          <div className="guardian-panel__scoreCard" style={{ textAlign: 'center', background: '#f9fafb', padding: '16px', borderRadius: '8px', marginBottom: '16px' }}>
             <div style={{ fontSize: '12px', color: '#6b7280' }}>Global Security Score</div>
             <div style={{ fontSize: '32px', fontWeight: 'bold', color: (typeof behavior?.score === 'number' ? behavior.score : 100) > 70 ? '#059669' : '#6b7280' }}>
               {typeof behavior?.score === 'number' ? `${behavior.score}/100` : '—'}
             </div>
          </div>

          <h4>🛠️ Improvement Suggestions</h4>
          <ul style={{ paddingLeft: '20px', fontSize: '13px' }}>
            {getSuggestions().map((s, i) => <li key={i} style={{ marginBottom: '4px' }}>{s}</li>)}
          </ul>

          <h4 style={{ display: 'flex', justifyContent: 'space-between' }}>
            📦 Extension Risk Cleanup
          </h4>
          <div style={{ maxHeight: '200px', overflowY: 'auto', fontSize: '12px', background: '#fff', borderRadius: '8px', padding: '8px', border: '1px solid #eee' }}>
            {(dashboardData?.extensionSummary || [])
              .slice()
              .sort((a, b) => b.riskScore - a.riskScore)
              .map((ext) => {
                const cat = getRiskCategory(ext.riskScore);
                const isUnused = ext.lastUsed && (Date.now() - ext.lastUsed > 30 * 24 * 60 * 60 * 1000);
                return (
                  <div key={ext.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f3f4f6', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontWeight: 'bold', color: '#111' }}>{ext.name}</div>
                      <div style={{ fontSize: '10px', color: cat.color }}>{cat.label} {isUnused ? '• ⏳ Unused > 30d' : ''}</div>
                    </div>
                    <button 
                      onClick={() => removeExtension(ext.id)}
                      style={{ background: '#fee2e2', color: '#dc2626', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '10px', fontWeight: 'bold' }}
                    >
                      Remove
                    </button>
                  </div>
                );
              })}
          </div>

          <h4 style={{ marginTop: '16px' }}>📍 Site Permissions</h4>
          <div style={{ maxHeight: '150px', overflowY: 'auto', fontSize: '12px' }}>
            {/* Fix: Use a fallback to empty array to prevent crash when dashboardData is null */}
            {(dashboardData?.sitePermissions || []).map((site, i) => (
              <div key={i} style={{ borderBottom: '1px solid #eee', padding: '6px 0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ maxWidth: '180px' }}>
                  <strong>{site.origin.replace('https://', '').replace('http://', '')}</strong>
                  <div style={{ fontSize: '10px', color: '#6b7280' }}>{site.permissions.join(', ')}</div>
                </div>
                <button 
                  onClick={() => revokeSite(site.origin)}
                  style={{ background: 'none', border: '1px solid #ccc', padding: '2px 6px', borderRadius: '4px', cursor: 'pointer', fontSize: '10px', color: '#111' }}
                >
                  Revoke
                </button>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <>
          {behavior && (
        <div className="guardian-panel__behavior">
          <h4>🧠 Behavior Analysis</h4>
          <p>
            Weekly Security Score:{' '}
            <strong>{typeof behavior.score === 'number' ? `${behavior.score}/100` : 'Not enough data yet'}</strong>
          </p>
          {behavior.habits.length > 0 && (
            <div className="guardian-panel__habits">
              <div className="guardian-panel__sectionTitle">Identified Patterns</div>
              <ul className="guardian-panel__habitList">
                {behavior.habits.map((h, i) => (
                  <li key={i} className="guardian-panel__habit">🚨 {h}</li>
                ))}
              </ul>
            </div>
          )}
          {behavior.suggestions.length > 0 && (
            <div className="guardian-panel__suggestions">
              <div className="guardian-panel__sectionTitle">Habit Improvement</div>
              <ul className="guardian-panel__suggestionList">
                {behavior.suggestions.map((s, i) => (
                  <li key={i}>💡 {s}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {extensionActivity && extensionActivity.length > 0 && (
        <div className="guardian-panel__activity">
          <h4>📡 Live Extension Activity</h4>
          <div className="guardian-panel__timeline">
            {(() => {
              const resolveExtensionName = (extensionId: string) => {
                const ext = dashboardData?.extensionSummary?.find((e) => e.id === extensionId);
                return ext?.name;
              };

              const formatted = extensionActivity
                .slice(-10)
                .reverse()
                .map((act) =>
                  formatActivity(act.type, act.detail, {
                    resolveExtensionName,
                    isWebStoreExtension: (id: string) => {
                      const ext = dashboardData?.extensionSummary?.find((e) => e.id === id);
                      return ext?.isFromWebStore ?? false;
                    }
                  }),
                );

              const grouped: Array<{ item: ReturnType<typeof formatActivity>; count: number }> = [];
              for (const item of formatted) {
                const existing = grouped.find((g) => g.item.key === item.key);
                if (existing) existing.count += 1;
                else grouped.push({ item, count: 1 });
              }

              const topItems = grouped.slice(0, 5);
              return topItems.map(({ item, count }, i) => (
                <div
                  key={`${item.key}:${i}`}
                  className="guardian-panel__activityItem"
                  style={{
                    paddingBottom: '10px',
                    marginBottom: i === topItems.length - 1 ? 0 : '10px',
                    borderBottom: i === topItems.length - 1 ? 'none' : '1px solid #f3f4f6',
                  }}
                >
                  <span
                    className="guardian-panel__activityType"
                    style={{
                      color:
                        item.tone === 'warning'
                          ? '#dc2626'
                          : item.tone === 'safe'
                            ? '#059669'
                            : '#111827',
                      fontWeight: item.tone === 'warning' ? 800 : undefined,
                    }}
                  >
                    {item.label}
                    {count > 1 ? ` (x${count})` : ''}
                  </span>
                  <div className="guardian-panel__subtle" style={{ fontSize: '11px' }}>
                    {item.message}
                  </div>
                  {item.details ? (
                    <div style={{ marginTop: '6px' }}>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          setActivityDetailsOpen((prev) => ({
                            ...prev,
                            [item.key]: !prev[item.key],
                          }));
                        }}
                        style={{
                          background: '#fff',
                          border: '1px solid #e5e7eb',
                          borderRadius: '6px',
                          padding: '4px 8px',
                          cursor: 'pointer',
                          fontSize: '11px',
                          color: '#111827',
                        }}
                      >
                        {activityDetailsOpen[item.key]
                          ? item.detailsButton?.open ?? 'Hide details'
                          : item.detailsButton?.closed ?? 'Details'}
                      </button>
                      {activityDetailsOpen[item.key] ? (
                        <div
                          className="guardian-panel__subtle"
                          style={{ fontSize: '11px', marginTop: '6px' }}
                        >
                          {item.details}
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              ));
            })()}
          </div>
        </div>
      )}

      <h4>Extension permissions</h4>
      {extensionSignals.length === 0 ? (
        <p className="guardian-panel__subtle">
          Couldn’t read extension manifest (or no relevant signals).
        </p>
      ) : (
        <div className="guardian-panel__signals">
          {extensionSignals.map((s) => {
            const education = getEducation(s);
            return (
              <div key={s.id} className="guardian-panel__signal" style={{ marginBottom: '12px' }}>
                <div style={{ paddingBottom: '8px' }}>
                  <strong style={{ display: 'block', marginBottom: '4px', fontSize: '13px' }}>
                    {education.title}
                  </strong>
                  <span style={{ fontSize: '11px', color: '#9ca3af' }}>
                    {s.category} · weight {s.weight}
                  </span>
                </div>
                <details>
                  <summary style={{ cursor: 'pointer', color: '#2563eb', fontSize: '12px', fontWeight: 500 }}>
                    💡 Learn more
                  </summary>
                  <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid rgba(0,0,0,0.1)', fontSize: '12px' }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '6px' }}>Why this can be risky:</div>
                    <ul style={{ paddingLeft: '16px', margin: '0 0 10px 0' }}>
                      {education.why.map((line, idx) => (
                        <li key={idx} style={{ marginBottom: '4px' }}>{line}</li>
                      ))}
                    </ul>
                    <div style={{ fontWeight: 'bold', marginBottom: '6px' }}>Safer next step:</div>
                    <ul style={{ paddingLeft: '16px', margin: 0 }}>
                      {education.safer.map((line, idx) => (
                        <li key={idx} style={{ marginBottom: '4px' }}>{line}</li>
                      ))}
                    </ul>
                  </div>
                </details>
              </div>
            );
          })}
        </div>
      )}

      <h4>Page signals</h4>
      {pageSignals.length === 0 ? (
        <div>
          <p className="guardian-panel__subtle">No risk signals detected on this page.</p>
          <p className="guardian-panel__subtle" style={{ marginTop: '4px' }}>
            This means the page looks normal right now. Continue using the site carefully and check the panel again if it asks for permissions or data.
          </p>
        </div>
      ) : (
        <div className="guardian-panel__signals">
          {pageSignals.map((s) => {
            const education = getEducation(s);
            return (
              <div key={s.id} className="guardian-panel__signal" style={{ marginBottom: '12px' }}>
                <div style={{ paddingBottom: '8px' }}>
                  <strong style={{ display: 'block', marginBottom: '4px', fontSize: '13px' }}>
                    {education.title}
                  </strong>
                  <span style={{ fontSize: '11px', color: '#9ca3af' }}>
                    {s.category} · weight {s.weight}
                  </span>
                </div>
                <details>
                  <summary style={{ cursor: 'pointer', color: '#2563eb', fontSize: '12px', fontWeight: 500 }}>
                    💡 Learn more
                  </summary>
                  <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid rgba(0,0,0,0.1)', fontSize: '12px' }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '6px' }}>Why this can be risky:</div>
                    <ul style={{ paddingLeft: '16px', margin: '0 0 10px 0' }}>
                      {education.why.map((line, idx) => (
                        <li key={idx} style={{ marginBottom: '4px' }}>{line}</li>
                      ))}
                    </ul>
                    <div style={{ fontWeight: 'bold', marginBottom: '6px' }}>Safer next step:</div>
                    <ul style={{ paddingLeft: '16px', margin: 0 }}>
                      {education.safer.map((line, idx) => (
                        <li key={idx} style={{ marginBottom: '4px' }}>{line}</li>
                      ))}
                    </ul>
                  </div>
                </details>
              </div>
            );
          })}
        </div>
      )}

      {injectedSignals && injectedSignals.length > 0 && (
        <>
          <h4>🔍 Real-Time Activity</h4>
          <div
            className="guardian-panel__injected-signals"
            style={{
              maxHeight: '220px',
              minHeight: '220px',
              overflowY: 'auto',
              overflowX: 'hidden',
              paddingRight: '4px',
            }}
          >
            {Array.from(
              (() => {
                const latest = new Map<string, InjectedSignal>();
                for (const s of injectedSignals) latest.set(s.signalId, s);
                return latest.values();
              })(),
            )
              .sort((a, b) => b.timestamp - a.timestamp)
              .slice(0, 10)
              .map((signal) => {
                const educationalContent = getEducationalContent(signal.signalId);
                if (!educationalContent) return null;

                const bgColor = getSeverityBg(educationalContent.severity);
                const textColor = getSeverityColor(educationalContent.severity);

                return (
                  <div
                    key={signal.signalId}
                    style={{
                      background: bgColor,
                      border: `1px solid ${textColor}`,
                      borderRadius: '6px',
                      padding: '12px',
                      marginBottom: '10px',
                      fontSize: '13px',
                      color: '#111827'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', marginBottom: '6px' }}>
                      <span style={{ fontSize: '16px', marginRight: '8px' }}>
                        {educationalContent.icon || '⚠️'}
                      </span>
                      <strong style={{ color: textColor }}>
                        {educationalContent.title}
                      </strong>
                      <span style={{ fontSize: '10px', marginLeft: 'auto', color: '#6b7280' }}>
                        {educationalContent.severity.toUpperCase()}
                      </span>
                    </div>

                    {/* Show the page origin and a human-friendly timestamp for each injected signal */}
                    <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '6px' }}>
                      {signal.origin ? <span>{signal.origin}</span> : null}
                      <span style={{ marginLeft: signal.origin ? 8 : 0 }}>{new Date(signal.timestamp).toLocaleString()}</span>
                    </div>

                    <details style={{ marginTop: '8px' }}>
                      <summary style={{ cursor: 'pointer', color: '#2563eb', fontSize: '12px', fontWeight: 500 }}>
                        💡 Learn more
                      </summary>
                      <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid rgba(0,0,0,0.1)', fontSize: '12px' }}>
                        <div style={{ fontWeight: 'bold', marginBottom: '6px' }}>Why this matters:</div>
                        <ul style={{ paddingLeft: '16px', margin: '0 0 10px 0' }}>
                          {educationalContent.why.map((line, idx) => (
                            <li key={idx} style={{ marginBottom: '4px' }}>{line}</li>
                          ))}
                        </ul>

                        <div style={{ fontWeight: 'bold', marginBottom: '6px' }}>What to do:</div>
                        <ul style={{ paddingLeft: '16px', margin: 0 }}>
                          {educationalContent.advice.map((line, idx) => (
                            <li key={idx} style={{ marginBottom: '4px' }}>{line}</li>
                          ))}
                        </ul>
                      </div>
                    </details>
                  </div>
                );
              })}
          </div>
        </>
      )}
        </>
      )}

      <div
        style={{
          marginTop: '16px',
          paddingTop: '10px',
          borderTop: '1px solid #e5e7eb',
          fontSize: '11px',
          color: '#6b7280',
        }}
      >
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '6px',
            alignItems: 'center',
          }}
        >
          <span>Open Source</span>
          <span>•</span>
          <span>Local Analysis Only</span>
          <span>•</span>
          <span>No Data Collection</span>
        </div>

        <div
          style={{
            marginTop: '6px',
            display: 'flex',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          <a
            href={GITHUB_REPO_URL}
            target="_blank"
            rel="noreferrer"
            style={{
              color: '#2563eb',
              textDecoration: 'none',
              fontWeight: 600,
            }}
          >
            GitHub Repository
          </a>
          <a
            href={SUPPORT_DEVELOPMENT_URL}
            target="_blank"
            rel="noreferrer"
            style={{
              color: '#2563eb',
              textDecoration: 'none',
              fontWeight: 600,
            }}
          >
            Support Development
          </a>
        </div>
      </div>
    </div>
  );
}
