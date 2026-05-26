# Permission Guardian — Project Notes

This document explains the extension architecture, permissions, code structure, and the implementation plan for security, compatibility, and milestones.

## Architecture (High Level)

```mermaid
flowchart LR
  subgraph Browser[Browser]
    P[Web Page (DOM)]
    MW[Main World Script\n`assets/inject.js`]
    CS[Content Script\n`assets/content-module.js`]
    UI[Injected Panel UI\nShadow DOM\n`src/panel/*`]
    BG[Background Service Worker\n`assets/background.js`]
    ST[(Extension Storage\nchrome.storage.local)]
  end

  P <-- hooks/intercepts --> MW
  MW -- CustomEvent: PG_SIGNAL_EVENT --> CS
  CS -- compute signals/risk --> UI
  CS -- runtime.sendMessage --> BG
  BG -- reads/writes --> ST
  BG -- executeScript (MAIN world)\n(some features) --> MW
```

### Key Data Flows

- **Page analysis flow**
  - `src/content/index.ts` runs on every page (`run_at: document_start`).
  - It collects signals via:
    - URL analysis (`src/engine/urlAnalyzer.ts`)
    - Website reputation / structure (`src/engine/websiteAnalyzer.ts`)
    - DOM analysis (cookies/storage/scripts/payment-field heuristics) (`src/engine/domAnalyzer.ts`)
    - Injected runtime signals from the main-world interceptor (`src/scripts/inject.ts` → built to `assets/inject.js`)
  - It scores risk via `src/engine/riskScorer.ts` and injects the panel UI (`src/panel/injectPanel.tsx`).

- **Runtime interception flow (MAIN world)**
  - `src/scripts/inject.ts` is loaded as a page `<script>` (web-accessible resource).
  - It hooks sensitive APIs (canvas fingerprinting, clipboard, geolocation, getUserMedia, storage reads/writes, basic network body inspection) and emits `PG_SIGNAL_EVENT` to the content script.

- **Background logging / persistence**
  - The content script sends events to the background (`src/background/index.ts`) using `runtime.sendMessage` for persistent logs, extension activity, and badge/score updates.
  - The background stores/aggregates data in `chrome.storage.local`.

## Extension Permissions (What and Why)

Defined in `public/manifest.json`.

- `activeTab`
  - Allows the extension to interact with the currently active tab when the user activates it (typical for extensions).

- `scripting`
  - Allows injecting scripts (e.g., executing scripts in a specific tab/world).
  - Used for MAIN-world injection when required (MV3 recommended approach).

- `notifications`
  - Enables user-facing notifications for important security events (if used by features).

- `storage`
  - Stores user settings (mode, preferences) and telemetry/history (risk updates, activity logs).

- `alarms`
  - Enables periodic background tasks (e.g., scheduled cleanup/refresh).

- `management`
  - Reads installed extensions metadata for the “Extension Risk Cleanup” / extension-permission auditing features.

- `host_permissions: ["<all_urls>"]`
  - Allows the content script to run on all sites and analyze pages everywhere.
  - This is powerful and should be treated as high-risk: keep data collection minimal, and prefer on-device processing.

## Code Structure (Backend / Frontend)

Even though this is not a traditional client/server app, you can think of it as:

### “Backend” (Extension background runtime)

- `src/background/index.ts`
  - Background service worker (MV3) message router, storage, and cross-tab actions.

### “Frontend” (UI + content logic)

- `src/content/index.ts`
  - Main content entry: runs analysis, computes risk, injects the panel, triggers overlays/banners.

- `src/panel/WarningPanel.tsx`
  - React UI that renders Live Analysis / Dashboard / Learn tabs.

- `src/panel/injectPanel.tsx`
  - Mounts the React UI into a Shadow DOM container (isolates styles from the page).

- `src/popup/*`
  - Popup UI for the extension action (if/when used).

### “Engine” (Detectors and scoring)

- `src/engine/*`
  - Risk signals, analyzers, scoring, learning/badges, and trackers.

### “Scripts” (MAIN world)

- `src/scripts/inject.ts`
  - MAIN-world interceptors compiled into a web-accessible asset (`assets/inject.js`).

## Security Considerations

- **Least privilege**
  - `<all_urls>` + `scripting` are powerful; keep logic on-device and avoid collecting sensitive content.
  - Prefer aggregated counts/metadata over raw values (e.g., cookie count vs cookie contents).

- **Sensitive data**
  - Avoid persisting secrets (card numbers, passwords, full cookies, tokens).
  - If detection requires matching patterns, do it in-memory and store only “detection happened” signals.

- **Injection safety**
  - Content script runs in an isolated world; MAIN-world script is required only for hooking native APIs.
  - Use strict message validation between contexts (page ↔ content script ↔ background).

- **Storage safety**
  - Treat `chrome.storage.local` as potentially inspectable by a local attacker; store minimal data, rotate/trim logs.

- **False positives**
  - Risk scoring is heuristic; UI should clearly communicate “signals detected” vs “confirmed malicious”.
  - Provide a way to dismiss banners and open details.

## Browser Compatibility Plan

- **Primary target: Chromium MV3**
  - Chrome and Edge (MV3) are the baseline; the build outputs a MV3 `dist/manifest.json`.

- **Firefox**
  - Firefox’s MV3 support differs from Chromium and changes over time.
  - Plan:
    1. Keep API access behind `globalThis.chrome ?? globalThis.browser` (already used in multiple places).
    2. Add a Firefox manifest variant if needed (different background/service worker behavior, permissions quirks).
    3. Run a compatibility checklist focusing on `scripting.executeScript`, `management`, and `web_accessible_resources`.

- **Graceful degradation**
  - If a permission/API is missing, disable the dependent feature rather than breaking the panel.

## Milestone Roadmap

1. **MVP Hardening**
   - Stabilize message routing and context-invalidated guards
   - Ensure safe defaults for storage/log retention

2. **Always-on Telemetry UI**
   - Show “what exists on the site” (counts + lists for scripts/cookies/storage) for *all* risk levels
   - Make signal explanation consistent across low/medium/high

3. **Threat Response UX**
   - Strong on-page warnings for high-risk pages (banners/overlays)
   - One-click open panel, dismiss, and “learn why”

4. **Compatibility & Packaging**
   - Validate Chrome/Edge packaging
   - Add Firefox build notes/variant if needed

5. **Privacy & Policy**
   - Document exactly what is collected, for how long, and where it is stored
   - Add optional “strict privacy mode” that stores only minimal aggregates

