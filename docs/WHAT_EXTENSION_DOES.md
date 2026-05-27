# Permission Guardian — What the Extension Does (File-by-File)

This document maps **features → code files** so it’s easy to understand what runs where (MV3 background service worker, content script, MAIN-world injection, and the on-page React panel).

## High-level behavior (runtime)

When you browse the web (non-iframe pages):

1. The **content script** starts at `document_start`, initializes trackers, computes risk signals, and can inject the on-page panel UI.
2. A **MAIN-world script** is injected to hook certain Web APIs (canvas, clipboard, fetch/XHR, storage, etc.) and emits runtime events.
3. The **background service worker** persists logs/settings in `chrome.storage.local`, updates phishing-list cache, and provides dashboard data (installed extensions + activity) to the UI panel.
4. The **panel UI** (React) shows:
   - Live analysis (page + extension signals)
   - Dashboard (logs, installed extensions summary, “modes”)
   - Learn (badges + quiz + educational explanations)

## Entry points / build outputs

- `vite.main.config.ts`, `vite.content.config.ts`
  - Build configuration for separate bundles (background + content module).
- `public/manifest.json`
  - MV3 manifest: permissions, background, content script, web-accessible resources.
- `dist/`
  - Build output that you load as an unpacked extension (see `README.md`).

## Manifest and permissions (what + why)

File: `public/manifest.json`

- `content_scripts.matches: ["<all_urls>"]`
  - Runs analysis on all sites (powerful; requires strong privacy controls and clear disclosures).
- `permissions: ["activeTab", "scripting", "notifications", "storage", "alarms", "management"]`
  - `scripting`: inject MAIN-world code where needed.
  - `storage`: store local settings + local logs.
  - `alarms`: periodic phishing-list refresh.
  - `management`: read installed extensions metadata for the extension dashboard / cleanup features.

## Content script (runs on web pages)

File: `src/content/index.ts`

Responsibilities:

- Bootstraps the extension **only for top-level pages** (skips iframes).
- Initializes:
  - Permission request tracking via background logging (`initPermissionTracker()`).
  - DOM mutation tracking for injected scripts/iframes (`initExtensionActivityTracker()`).
- Collects and scores signals:
  - URL signals: `src/engine/urlAnalyzer.ts`
  - Website signals (reputation heuristics): `src/engine/websiteAnalyzer.ts`
  - DOM signals: `src/engine/domAnalyzer.ts`
  - Extension manifest signals (self-analysis): `src/engine/extensionPermissionsAnalyzer.ts`
  - Risk scoring: `src/engine/riskScorer.ts` (`calculateRisk`)
- Loads a **local phishing cache** (hashes stored in `chrome.storage.local`) and marks a page as known phishing if its hostname hash is present.
- UI behavior:
  - Toggles the panel when the background sends `PG_TOGGLE_PANEL`.
  - Updates extension badge risk via `PG_RISK_UPDATE`.
  - Auto-shows a harmful-site banner at high scores and a stronger overlay on suspected payment-field interactions.

Notes:

- A second injection method exists:
  - `injectMainWorldScript()` injects `assets/inject.js` via `<script src=...>` as a web-accessible resource.
  - Background also injects `scripts/inject.js` into `world: "MAIN"` for some features (see `src/background/index.ts`).

## MAIN-world runtime hooks (page context)

File: `src/scripts/inject.ts`

Runs in the page’s MAIN world and emits `CustomEvent("PG_SIGNAL_EVENT")` so the content script can capture runtime signals.

Hooks:

- Canvas fingerprinting attempts (`toDataURL`, `toBlob`)
- Network exfiltration heuristic:
  - Intercepts `fetch` and `XMLHttpRequest.send` to detect card-like patterns in outbound bodies (best-effort).
- Clipboard reads/writes (`navigator.clipboard.*`)
- Motion/orientation sensors (one-time events)
- Geolocation (`getCurrentPosition`, `watchPosition`)
- Camera/microphone requests via `getUserMedia`
- Storage reads/writes (`Storage.getItem`, `Storage.setItem`)

Output:

- Emits `InjectedSignal` objects (see `src/engine/types.ts`) consumed by the panel as “Real-Time Activity”.

## Background service worker (persistent logic)

File: `src/background/index.ts`

Responsibilities:

- Receives content-script messages and persists local logs:
  - Permission requests history: `pg_permission_history`
  - Extension activity log: `pg_extension_activity`
  - Last used timestamp: `pg_extension_last_used`
- Phishing list cache (local):
  - Fetches OpenPhish feed (network call) and stores **SHA-256 hashes of hostnames** in local storage:
    - `pg_phishing_hashes`
    - `pg_phishing_last_update`
  - Refresh schedule via alarms (`pg_update_phishing_lists`).
- Injects MAIN-world script using `chrome.scripting.executeScript({ world: "MAIN" })` when tabs load.
- Provides dashboard data to the panel:
  - Collects installed extensions via `api.management.getAll()`
  - Returns logs + extensions list to the panel on `GET_DASHBOARD_DATA`.

## Panel injection (UI mounting)

File: `src/panel/injectPanel.tsx`

Responsibilities:

- Creates the floating container `#guardian-root` and attaches a **Shadow DOM** to isolate styles.
- Wires close behaviors (Esc, outside click if enabled).
- Calls `analyzeBehavior()` and fetches activity logs from storage via `extensionApi`.
- Renders the React panel:
  - Component: `src/panel/WarningPanel.tsx`

## Panel UI (React)

File: `src/panel/WarningPanel.tsx`

Responsibilities:

- Main UI and product logic (tabs + rendering + many heuristics):
  - **Live Analysis**: overall/page/extension scores + signals with “Learn more”
  - **Dashboard**:
    - Protection mode (strict/balanced/silent) stored as `pg_mode`
    - Site permission history summary
    - Installed extension summary (uses background-provided list)
    - “Extension Risk Cleanup” actions (remove extension / clear site data via `extensionApi`)
  - **Learn**:
    - Badges (from `src/engine/learningEngine.ts`)
    - Quiz (from `src/engine/learningEngine.ts`)
- Maps signals to education text:
  - Uses `getEducationalContent`, `getSeverityColor`, `getSeverityBg` (`src/utils/educationalContent.ts`)
  - Also contains its own education map for many signal IDs.
- “Trusted extension” heuristics (current implementation):
  - Local allowlist by extension ID + name keywords.

## Engine (signals + scoring)

Risk scoring:

- `src/engine/riskScorer.ts`
  - `calculateRisk(signals)` → `{ score, level }` used by `src/content/index.ts`.

Signal definitions:

- `src/engine/types.ts`
  - `RiskSignal`, `InjectedSignal`, `RiskLevel`.

Page analyzers:

- `src/engine/urlAnalyzer.ts`
  - URL-based phishing heuristics (length, @ symbol, IP host, punycode, redirect params, etc.).
- `src/engine/websiteAnalyzer.ts`
  - Site-level heuristics (HTTP vs HTTPS, new domains, typosquatting heuristics, known-phishing integration).
- `src/engine/domAnalyzer.ts`
  - DOM heuristics (password fields, payment input detection, third-party scripts/iframes, storage presence, etc.).

Extension analyzer:

- `src/engine/extensionPermissionsAnalyzer.ts`
  - Analyzes a manifest-like object for risky permissions and host access patterns.
  - Includes “purpose mismatch” heuristics based on description/name keywords (English + Bulgarian keyword support).

Behavior and learning:

- `src/engine/behaviorAnalyzer.ts`
  - Computes behavior metrics used by the panel.
- `src/engine/learningEngine.ts`
  - Quiz questions and badge definitions.

Activity tracking:

- `src/engine/extensionActivityTracker.ts`
  - MutationObserver that logs injected `SCRIPT`/`IFRAME` additions (extension or dynamic).

Permission tracking:

- `src/engine/permissionTracker.ts`
  - Requests background injection and logs permission-related proxy events to the background.
  - Shows small on-page toast alerts depending on mode.

## Utilities (browser API wrappers + education helpers)

- `src/utils/extensionApi.ts`
  - Wrapper for messaging/storage actions (panel → background).
- `src/utils/educationalContent.ts`
  - Signal → explanation/advice map + severity colors/background helpers.
- `src/utils/helper.ts`
  - Shared helpers (project-specific).

## Root-level legacy files (likely not used by the Vite builds)

These exist at the repo root and may be older prototypes or placeholders:

- `background.js`, `content.js`, `popup.js`, `popup.html`

The active MV3 build uses:

- Background: `src/background/index.ts` → `dist/assets/background.js`
- Content: `src/content/index.ts` → `dist/assets/content-module.js`

## “What data is stored locally?”

Stored in `chrome.storage.local` (see `src/background/index.ts`):

- `pg_permission_history` (permission log history; bounded + time-windowed)
- `pg_extension_activity` (script/iframe injection/activity log; bounded + time-windowed)
- `pg_extension_last_used` (timestamp)
- `pg_phishing_hashes` (hashed hostnames from OpenPhish feed)
- `pg_phishing_last_update` (timestamp)
- `pg_mode` (strict/balanced/silent mode; set by the panel)

## How to generate a PDF (optional)

If you have Pandoc installed:

```bash
pandoc docs/WHAT_EXTENSION_DOES.md -o docs/WHAT_EXTENSION_DOES.pdf
```

