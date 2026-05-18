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
  try {
    const currentHost = window.location.hostname;
    const scripts = Array.from(document.scripts);
    const thirdParty = scripts.filter((s) => {
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
