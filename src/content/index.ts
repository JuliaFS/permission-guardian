import { analyzeDOM } from "../engine/domAnalyzer";
import { analyzeExtensionManifest } from "../engine/extensionPermissionsAnalyzer";
import { calculateRisk } from "../engine/riskScorer";
import { analyzeUrl } from "../engine/urlAnalyzer";
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
    function compute() {
      const url = window.location.href;
      const urlSignals = analyzeUrl(url);
      const domSignals = analyzeDOM();
      const pageSignals = [...urlSignals, ...domSignals];

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

    function reportBadgeRisk() {
      try {
        const { overall } = compute();
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

    function togglePanel() {
      const existing = document.getElementById("guardian-root");
      if (existing) {
        existing.remove();
        return;
      }

      const showCloseButton =
        globalThis.localStorage?.getItem("pg_show_close_button") === "1";

      const {
        overall,
        pageRisk,
        extensionRisk,
        pageSignals,
        extensionSignals,
        injectedSignals: currentSignals,
      } = compute();

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
        { showCloseButton, injectedSignals: currentSignals },
      );
    }

    runtime?.onMessage?.addListener((message: any) => {
      console.log("[PG] Message received in content script:", message.type);
      if (message?.type === "PG_TOGGLE_PANEL" && runtime?.id) {
        togglePanel();
      }
    });

    // Update the toolbar badge for this tab once the page is ready.
    // (Keeps the icon informative even when the panel is closed.)
    if (document.readyState === "complete") {
      injectMainWorldScript();
      reportBadgeRisk();
      checkAutoShow();
    } else {
      window.addEventListener(
        "load",
        () => {
          injectMainWorldScript();
          reportBadgeRisk();
          checkAutoShow();
        },
        { once: true },
      );
    }

    function checkAutoShow() {
      // If you want the modal to appear automatically like "it was" for high risk:
      const { overall } = compute();
      if (
        (overall.level as string) === "high" &&
        !document.getElementById("guardian-root")
      ) {
        togglePanel();
      }
    }
  }
}
