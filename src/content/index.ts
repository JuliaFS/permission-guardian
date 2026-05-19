import { analyzeDOM } from "../engine/domAnalyzer";
import { analyzeExtensionManifest } from "../engine/extensionPermissionsAnalyzer";
import { calculateRisk } from "../engine/riskScorer";
import { analyzeUrl } from "../engine/urlAnalyzer";
import { analyzeWebsite } from "../engine/websiteAnalyzer";
import { injectPanel } from "../panel/injectPanel";
import { initExtensionActivityTracker } from "../engine/extensionActivityTracker";
import { initPermissionTracker } from "../engine/permissionTracker";
import type { InjectedSignal } from "../engine/types";

if (window.top !== window.self) {
  // Avoid injecting into iframes.
  // (Also keeps analysis cost down on complex pages.)
  // eslint-disable-next-line no-console
  console.debug("Permission Guardian: skipping iframe");
} else {
  initPermissionTracker();
  initExtensionActivityTracker();

  const runtime =
    (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime;
  const api = (globalThis as any).chrome ?? (globalThis as any).browser;

  const PHISHING_HASHES_KEY = "pg_phishing_hashes";
  let phishingHashes: Set<string> | null = null;
  let phishingHashesLoadedAt = 0;
  const hostnameHashCache = new Map<string, string>();

  function normalizeHostname(hostname: string) {
    return hostname.toLowerCase().replace(/^www\./, "");
  }

  async function sha256Hex(value: string): Promise<string> {
    const cached = hostnameHashCache.get(value);
    if (cached) return cached;
    const data = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", data);
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    hostnameHashCache.set(value, hex);
    return hex;
  }

  async function loadPhishingHashes(): Promise<Set<string>> {
    // Reload at most once per minute to avoid hammering storage.
    if (phishingHashes && Date.now() - phishingHashesLoadedAt < 60_000) return phishingHashes;

    const result = await new Promise<any>((resolve) => {
      api?.storage?.local?.get?.([PHISHING_HASHES_KEY], (data: any) => resolve(data || {}));
    });

    const list = Array.isArray(result?.[PHISHING_HASHES_KEY]) ? result[PHISHING_HASHES_KEY] : [];
    phishingHashes = new Set<string>(list);
    phishingHashesLoadedAt = Date.now();
    return phishingHashes;
  }

  // Inject the main-world script for Canvas/Clipboard/Sensor interception
  function injectMainWorldScript() {
    try {
      const script = document.createElement('script');
      script.src = runtime?.getURL?.('assets/inject.js');
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
    } catch (error: unknown) {
      console.debug('[PG] Failed to inject main-world script:', error);
    }
  }

  // Storage for signals collected from inject.ts
  const injectedSignals: InjectedSignal[] = [];

  // Listen for signals from inject.ts (main world)
  window.addEventListener('PG_SIGNAL_EVENT', (event: any) => {
    const signal: InjectedSignal = event.detail;
    injectedSignals.push(signal);
    
    // Throttle: only keep last 100 signals
    if (injectedSignals.length > 100) {
      injectedSignals.shift();
    }
    
    console.debug('[PG] Captured signal:', signal);
  });

  // Check if extension context is still valid
  if (!runtime?.id) {
    // Context invalidated, do nothing
  } else {
    async function compute() {
      const url = window.location.href;
      const urlSignals = analyzeUrl(url);
      const urlObj = new URL(url);
      const hostname = normalizeHostname(urlObj.hostname);
      const hashes = await loadPhishingHashes();
      const hostnameHash = await sha256Hex(hostname);
      const isKnownPhishing = hashes.has(hostnameHash);

      const websiteSignals = analyzeWebsite(url, { knownPhishing: isKnownPhishing });
      const domSignals = analyzeDOM();
      const pageSignals = [...urlSignals, ...websiteSignals, ...domSignals];

      const manifest = (() => {
        try {
          return runtime?.getManifest?.();
        } catch (error) {
          console.debug(
            "Permission Guardian: failed to get manifest, extension context may be invalidated",
          );
          return null;
        }
      })();
      const extensionSignals = manifest
        ? analyzeExtensionManifest(manifest)
        : [];

      const allSignals = [...pageSignals, ...extensionSignals];
      const overall = calculateRisk(allSignals);
      const pageRisk = calculateRisk(pageSignals);
      const extensionRisk = calculateRisk(extensionSignals);

      return {
        overall,
        pageRisk,
        extensionRisk,
        pageSignals,
        extensionSignals,
        injectedSignals,
      };
    }

    async function reportBadgeRisk() {
      try {
        const { overall } = await compute();
        runtime?.sendMessage?.({
          type: "PG_RISK_UPDATE",
          level: overall.level,
          score: overall.score,
        });
      } catch (error) {
        // Extension context invalidated, silently fail
        console.debug(
          "Permission Guardian: extension context invalidated during risk update",
        );
      }
    }

    async function togglePanel() {
      const existing = document.getElementById("guardian-root");
      if (existing) {
        existing.remove();
        return;
      }

      const showCloseButton =
        globalThis.localStorage?.getItem("pg_show_close_button") !== "0";

      const closeOnOutsideClick =
        globalThis.localStorage?.getItem("pg_close_on_outside_click") !== "0";

      const {
        overall,
        pageRisk,
        extensionRisk,
        pageSignals,
        extensionSignals,
        injectedSignals: currentSignals,
      } = await compute();

      try {
        runtime?.sendMessage?.({
          type: "PG_RISK_UPDATE",
          level: overall.level,
          score: overall.score,
        });
      } catch (error) {
        // Extension context invalidated, silently fail
        console.debug(
          "Permission Guardian: extension context invalidated during panel toggle",
        );
        return;
      }

      injectPanel(
        {
          overall,
          page: pageRisk,
          extension: extensionRisk,
        },
        { page: pageSignals, extension: extensionSignals },
        { showCloseButton, closeOnOutsideClick, injectedSignals: currentSignals },
      );
    }

    runtime?.onMessage?.addListener((message: any) => {
      console.log("[PG] Message received in content script:", message.type);
      if (message?.type === "PG_TOGGLE_PANEL" && runtime?.id) {
        void togglePanel();
      }
    });

    // Update the toolbar badge for this tab once the page is ready.
    // (Keeps the icon informative even when the panel is closed.)
    if (document.readyState === "complete") {
      injectMainWorldScript();
      void reportBadgeRisk();
      void checkAutoShow();
    } else {
      window.addEventListener(
        "load",
        () => {
          injectMainWorldScript();
          void reportBadgeRisk();
          void checkAutoShow();
        },
        { once: true },
      );
    }

    async function checkAutoShow() {
      // If you want the modal to appear automatically like "it was" for high risk:
      const { overall } = await compute();
      if (
        (overall.level as string) === "high" &&
        !document.getElementById("guardian-root")
      ) {
        void togglePanel();
      }
    }
  }
}
