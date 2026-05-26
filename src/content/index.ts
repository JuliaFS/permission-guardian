import { analyzeDOM } from "../engine/domAnalyzer";
import { analyzeExtensionManifest } from "../engine/extensionPermissionsAnalyzer";
import { calculateRisk } from "../engine/riskScorer";
import { analyzeUrl } from "../engine/urlAnalyzer";
import { analyzeWebsite } from "../engine/websiteAnalyzer";
import { injectPanel } from "../panel/injectPanel";
import { initExtensionActivityTracker } from "../engine/extensionActivityTracker";
import { initPermissionTracker } from "../engine/permissionTracker";
import type { InjectedSignal, RiskSignal } from "../engine/types";

if (window.top !== window.self) {
  // Avoid injecting into iframes to optimize tracking resource allocations.
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
    // Reload at most once per minute to avoid overloading storage channels.
    if (phishingHashes && Date.now() - phishingHashesLoadedAt < 60_000)
      return phishingHashes;

    const result = await new Promise<any>((resolve) => {
      api?.storage?.local?.get?.([PHISHING_HASHES_KEY], (data: any) =>
        resolve(data || {}),
      );
    });

    const list = Array.isArray(result?.[PHISHING_HASHES_KEY])
      ? result[PHISHING_HASHES_KEY]
      : [];
    phishingHashes = new Set<string>(list);
    phishingHashesLoadedAt = Date.now();
    return phishingHashes;
  }

  // Inject the main-world interceptor engine script (Canvas, Clipboard, Web API Hooks)
  function injectMainWorldScript() {
    try {
      const script = document.createElement("script");
      script.src = runtime?.getURL?.("assets/inject.js");
      script.onload = () => script.remove();
      (document.head || document.documentElement).appendChild(script);
    } catch (error: unknown) {
      console.debug("[PG] Failed to inject main-world script:", error);
    }
  }

  // Under-the-hood real-time telemetry signal tracker pool
  const injectedSignals: InjectedSignal[] = [];

  // Listen for low-level Web API interceptions broadcasted from inject.ts
  window.addEventListener("PG_SIGNAL_EVENT", (event: any) => {
    const signal: InjectedSignal = event.detail;
    injectedSignals.push(signal);

    // Throttle array length to prevent memory leakage over long browsing sessions
    if (injectedSignals.length > 100) {
      injectedSignals.shift();
    }

    console.debug("[PG] Captured runtime signature signal:", signal);
  });

  // Structural runtime execution safety guard
  if (!runtime?.id) {
    // Context invalidated, terminate routine loops cleanly
  } else {
    async function compute() {
      const url = window.location.href;
      let urlSignals: any[] = [];
      try {
        urlSignals = analyzeUrl(url);
      } catch (error) {
        console.warn("[PG] URL analysis failed:", error);
      }

      const urlObj = new URL(url);
      const hostname = normalizeHostname(urlObj.hostname);
      const hashes = await loadPhishingHashes();
      const hostnameHash = await sha256Hex(hostname);
      const isKnownPhishing = hashes.has(hostnameHash);

      let websiteSignals: any[] = [];
      try {
        websiteSignals = analyzeWebsite(url, {
          knownPhishing: isKnownPhishing,
        });
      } catch (error) {
        console.warn("[PG] Website analysis failed:", error);
      }

      let domSignals: any[] = [];
      try {
        domSignals = analyzeDOM();
      } catch (error) {
        console.warn("[PG] DOM analysis failed:", error);
      }

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
      let extensionSignals: any[] = [];
      if (manifest) {
        try {
          extensionSignals = analyzeExtensionManifest(manifest);
        } catch (error) {
          console.warn("[PG] Extension manifest analysis failed:", error);
        }
      }

      const allSignals = [...pageSignals, ...extensionSignals];
      let overall = { level: "info", score: 0 };
      let pageRisk = { level: "info", score: 0 };
      let extensionRisk = { level: "info", score: 0 };
      
      try {
        overall = calculateRisk(allSignals);
        pageRisk = calculateRisk(pageSignals);
        extensionRisk = calculateRisk(extensionSignals);
      } catch (error) {
        console.warn("[PG] Risk calculation failed:", error);
      }

      return {
        overall,
        pageRisk,
        extensionRisk,
        pageSignals,
        extensionSignals,
        injectedSignals: [...injectedSignals], // Shallow copy arrays to prevent runtime state drop-outs
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
        console.debug(
          "Permission Guardian: extension context invalidated during badge risk update",
        );
      }
    }

    async function togglePanel() {
      try {
        const existing = document.getElementById("guardian-root");
        if (existing) {
          existing.remove();
          return;
        }

        const showCloseButton =
          globalThis.localStorage?.getItem("pg_show_close_button") !== "0";

        const closeOnOutsideClick =
          globalThis.localStorage?.getItem("pg_close_on_outside_click") !== "0";

        let computeResult;
        try {
          computeResult = await compute();
        } catch (analyzeError) {
          console.error(
            "[PG] Analysis failed on this page, showing panel with limited data:",
            analyzeError,
          );
          // Fallback: show panel with empty signals if analysis fails
          computeResult = {
            overall: { level: "info", score: 0 },
            pageRisk: { level: "info", score: 0 },
            extensionRisk: { level: "info", score: 0 },
            pageSignals: [],
            extensionSignals: [],
            injectedSignals: [...injectedSignals],
          };
        }

        const {
          overall,
          pageRisk,
          extensionRisk,
          pageSignals,
          extensionSignals,
          injectedSignals: currentSignals,
        } = computeResult;

        try {
          runtime?.sendMessage?.({
            type: "PG_RISK_UPDATE",
            level: overall.level,
            score: overall.score,
          });
        } catch (error) {
          console.debug(
            "Permission Guardian: extension context invalidated during panel initialization",
          );
          return;
        }

        try {
          injectPanel(
            {
              overall,
              page: pageRisk,
              extension: extensionRisk,
            },
            { page: pageSignals, extension: extensionSignals },
            {
              showCloseButton,
              closeOnOutsideClick,
              injectedSignals: currentSignals,
            },
          );
        } catch (injectError) {
          console.error("[PG] Failed to inject panel:", injectError);
        }
      } catch (error) {
        console.error("[PG] Unexpected error in togglePanel:", error);
      }
    }

    runtime?.onMessage?.addListener((message: any) => {
      console.log("[PG] Message received in content script:", message.type);
      if (message?.type === "PG_TOGGLE_PANEL" && runtime?.id) {
        void togglePanel();
      }
    });

    // Fire evaluation checks immediately once document thread layers anchor
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

    function isPotentialPaymentInput(element: EventTarget | null) {
      if (!(element instanceof HTMLElement)) return false;
      return element.matches(
        "input[name*='card'], input[name*='cc'], input[name*='cvv'], input[name*='cvc'], input[autocomplete*='cc-'], input[placeholder*='card'], input[placeholder*='cvv'], input[placeholder*='cvc']",
      );
    }

    const HARMFUL_BANNER_ID = "guardian-harmful-site-banner";
    const HARMFUL_BANNER_SESSION_KEY = "pg_harmful_banner_shown";

    function removeHarmfulSiteBanner() {
      document.getElementById(HARMFUL_BANNER_ID)?.remove();
    }

    function buildHarmfulReasons(input: {
      pageSignals: RiskSignal[];
      injectedSignals: InjectedSignal[];
    }): string[] {
      const reasons: string[] = [];
      const seen = new Set<string>();

      const add = (text: string) => {
        const trimmed = (text || "").trim();
        if (!trimmed) return;
        if (seen.has(trimmed)) return;
        seen.add(trimmed);
        reasons.push(trimmed);
      };

      // 1) Prefer hard-runtime detections first (ex: card data exfiltration)
      const cardLeak = input.injectedSignals.find(
        (s) => s.signalId === "card_data_exfiltration" && s.action === "detected",
      );
      if (cardLeak) {
        add(
          "Warning: Possible card data exfiltration detected (sensitive payment-like data sent over the network).",
        );
      }

      // 2) Add top weighted page signals (skip negative weights like “official gateway detected”)
      const topSignals = [...(input.pageSignals || [])]
        .filter((s) => Number.isFinite(s.weight) && s.weight > 0 && !!s.message)
        .sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0))
        .slice(0, 4);

      for (const s of topSignals) add(s.message);

      return reasons.slice(0, 4);
    }

    function showHarmfulSiteBanner(input: {
      score: number;
      reasons: string[];
      onOpenPanel: () => void;
    }) {
      if (document.getElementById(HARMFUL_BANNER_ID)) return;

      const root = document.createElement("div");
      root.id = HARMFUL_BANNER_ID;
      Object.assign(root.style, {
        position: "fixed",
        top: "18px",
        left: "18px",
        zIndex: "2147483647",
        maxWidth: "520px",
        width: "calc(100vw - 36px)",
        background: "#fff",
        color: "#111827",
        borderRadius: "12px",
        boxShadow: "0 18px 40px rgba(0,0,0,0.25)",
        border: "3px solid #dc2626",
        padding: "14px 14px 12px",
        boxSizing: "border-box",
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
        animation: "pg-blink-border 0.8s linear infinite",
      } as any);

      const reasonsHtml =
        input.reasons?.length > 0
          ? `<ul style="margin:8px 0 0; padding-left:18px; color:#b91c1c; font-size:13px; line-height:1.45;">
              ${input.reasons
                .slice(0, 4)
                .map((r) => `<li style="margin:4px 0;">${r}</li>`)
                .join("")}
            </ul>`
          : `<div style="margin-top:8px; color:#b91c1c; font-size:13px; line-height:1.45;">
              Risk score is high, but no specific reason was provided.
            </div>`;

      root.innerHTML = `
        <style>
          @keyframes pg-blink-border {
            0%, 100% { border-color: #dc2626; box-shadow: 0 18px 40px rgba(0,0,0,0.25), 0 0 0 0 rgba(220,38,38,0.0); }
            50% { border-color: #f59e0b; box-shadow: 0 18px 40px rgba(0,0,0,0.25), 0 0 0 6px rgba(220,38,38,0.18); }
          }
          #${HARMFUL_BANNER_ID} button { font-family: inherit; }
        </style>
        <div style="display:flex; align-items:flex-start; gap:10px;">
          <div style="font-size:20px; line-height:1;">⚠️</div>
          <div style="flex:1; min-width:0;">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:10px;">
              <div style="font-weight:800; color:#b91c1c; font-size:14px;">
                This page may be harmful
              </div>
              <button id="pg-harmful-close" style="border:none; background:transparent; cursor:pointer; color:#6b7280; font-size:16px; padding:2px 6px;">
                ×
              </button>
            </div>
            <div style="margin-top:4px; display:flex; align-items:center; justify-content:space-between; gap:10px;">
              <div style="color:#6b7280; font-size:12px;">
                Permission Guardian detected high-risk signals on this site.
              </div>
              <div style="color:#dc2626; font-weight:800; font-size:12px;">
                Risk: ${input.score}/100
              </div>
            </div>
            ${reasonsHtml}
            <div style="margin-top:10px; display:flex; gap:8px; justify-content:flex-end;">
              <button id="pg-harmful-open" style="border:1px solid #e5e7eb; background:#f9fafb; color:#111827; padding:7px 10px; border-radius:8px; cursor:pointer; font-size:12px; font-weight:700;">
                Open details
              </button>
              <button id="pg-harmful-dismiss" style="border:none; background:#dc2626; color:#fff; padding:7px 10px; border-radius:8px; cursor:pointer; font-size:12px; font-weight:800;">
                Dismiss
              </button>
            </div>
          </div>
        </div>
      `;

      document.body.appendChild(root);

      const dismiss = () => {
        try {
          globalThis.sessionStorage?.setItem(HARMFUL_BANNER_SESSION_KEY, "1");
        } catch {
          // ignore
        }
        removeHarmfulSiteBanner();
      };

      root.querySelector("#pg-harmful-close")?.addEventListener("click", dismiss);
      root
        .querySelector("#pg-harmful-dismiss")
        ?.addEventListener("click", dismiss);
      root.querySelector("#pg-harmful-open")?.addEventListener("click", () => {
        input.onOpenPanel();
      });
    }

    function removeRiskInterceptor() {
      const overlay = document.getElementById("guardian-warning-overlay");
      if (overlay) overlay.remove();
    }

    function showRiskInterceptorBanner(score: number) {
      if (document.getElementById("guardian-warning-overlay")) return;

      const overlay = document.createElement("div");
      overlay.id = "guardian-warning-overlay";
      Object.assign(overlay.style, {
        position: "fixed",
        inset: "0",
        background: "rgba(15, 23, 42, 0.85)", // Sleek modern slate backdrop
        backdropFilter: "blur(4px)",
        color: "#fff",
        zIndex: "2147483647",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        padding: "24px",
        boxSizing: "border-box",
      });

      const messageBox = document.createElement("div");
      Object.assign(messageBox.style, {
        maxWidth: "580px",
        width: "100%",
        background: "#1e293b",
        borderRadius: "16px",
        padding: "28px",
        boxShadow: "0 25px 50px -12px rgba(0,0,0,0.5)",
        fontFamily: "system-ui, -apple-system, sans-serif",
        border: "1px solid #334155",
      });

      messageBox.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:20px;">
          <div>
            <h2 style="margin:0 0 10px; color:#ef4444; font-size:22px; font-weight:700; line-height:1.3; display:flex; align-items:center; gap:8px;">
              🛑 POSSIBLE CREDIT CARD SKIMMER DETECTED
            </h2>
            <p style="margin:0 0 16px; color:#e2e8f0; font-size:15px; line-height:1.6;">
              Permission Guardian detected that this website collects credit card records directly onto an un-sandboxed form layer instead of loading an isolated payment window (like verified Stripe or PayPal containers). Entering your billing data here carries an extreme risk of financial theft.
            </p>
            <div style="background:#0f172a; padding:10px 14px; border-radius:8px; border:1px solid #1e293b; display:flex; justify-content:space-between; align-items:center;">
              <span style="color:#94a3b8; font-size:13px; font-weight:500;">Calculated Page Risk Score:</span>
              <span style="color:#ef4444; font-size:14px; font-weight:700;">${score} / 100</span>
            </div>
          </div>
          <div style="display:flex; justify-content:flex-end;">
            <button id="guardian-warning-close" style="border:none; background:#ef4444; color:#fff; padding:10px 22px; border-radius:8px; cursor:pointer; font-size:14px; font-weight:600; transition: background 0.2s;">
              Acknowledge & Close
            </button>
          </div>
        </div>
      `;

      messageBox
        .querySelector("#guardian-warning-close")
        ?.addEventListener("click", () => {
          removeRiskInterceptor();
        });

      overlay.appendChild(messageBox);
      document.body.appendChild(overlay);
    }

    async function checkAutoShow() {
      const { overall, pageSignals, injectedSignals } = await compute();

      const alreadyShown = (() => {
        try {
          return globalThis.sessionStorage?.getItem(HARMFUL_BANNER_SESSION_KEY) ===
            "1";
        } catch {
          return false;
        }
      })();

      // Show a visible on-page warning rectangle if the site looks harmful.
      if (!alreadyShown && overall.score >= 80) {
        const reasons = buildHarmfulReasons({ pageSignals, injectedSignals });
        showHarmfulSiteBanner({
          score: overall.score,
          reasons,
          onOpenPanel: () => {
            if (!document.getElementById("guardian-root")) {
              void togglePanel();
            }
          },
        });
      }

      // Open the warning panel when the computed danger level is high or critical.
      if (
        (overall.level as string) === "high" ||
        (overall.level as string) === "critical"
      ) {
        if (!document.getElementById("guardian-root")) {
          void togglePanel();
        }
      }

      document.addEventListener(
        "focusin",
        async (event) => {
          if (!isPotentialPaymentInput(event.target)) return;

          const { overall, pageSignals, injectedSignals } = await compute();

          // Ensure the user sees a non-blocking warning even before the blocker kicks in.
          const wasShown = (() => {
            try {
              return (
                globalThis.sessionStorage?.getItem(
                  HARMFUL_BANNER_SESSION_KEY,
                ) === "1"
              );
            } catch {
              return false;
            }
          })();
          if (!wasShown && overall.score >= 80) {
            const reasons = buildHarmfulReasons({ pageSignals, injectedSignals });
            showHarmfulSiteBanner({
              score: overall.score,
              reasons,
              onOpenPanel: () => {
                if (!document.getElementById("guardian-root")) {
                  void togglePanel();
                }
              },
            });
          }

          // CORRECTED: Trigger the blocker overlay if the danger score is high (>= 80)
          if (overall.score >= 80) {
            showRiskInterceptorBanner(overall.score);
          }
        },
        true,
      );

      window.addEventListener("beforeunload", () => {
        removeRiskInterceptor();
        removeHarmfulSiteBanner();
      });
    }
  }
}
