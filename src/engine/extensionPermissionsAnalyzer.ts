import type { RiskSignal } from "./types";

type ManifestLike = {
  name?: string;
  description?: string;
  permissions?: string[];
  optional_permissions?: string[];
  host_permissions?: string[];
  optional_host_permissions?: string[];
  background?: {
    service_worker?: string;
    persistent?: boolean;
  };
  content_scripts?: Array<{
    matches?: string[];
  }>;
};

const DANGEROUS_PERMISSIONS: Array<{
  id: string;
  permission: string;
  weight: number;
  message: string;
}> = [
  {
    id: "ext_perm_tabs",
    permission: "tabs",
    weight: 35,
    message: "Has access to your open tabs (titles/URLs), which can reveal sensitive browsing activity",
  },
  {
    id: "ext_perm_cookies",
    permission: "cookies",
    weight: 45,
    message: "Can read/modify cookies, which can expose logins and tracking identifiers",
  },
  {
    id: "ext_perm_webRequest",
    permission: "webRequest",
    weight: 50,
    message: "Can observe/modify network requests, which can be used for tracking, injection, or data interception",
  },
  {
    id: "ext_perm_history",
    permission: "history",
    weight: 45,
    message: "Can read your browsing history, which may reveal private interests and behavior",
  },
  {
    id: "ext_perm_activeTab",
    permission: "activeTab",
    weight: 15,
    message: "Can access the currently active tab after you click the extension (still powerful on sensitive pages)",
  },
  {
    id: "ext_perm_clipboardRead",
    permission: "clipboardRead",
    weight: 50,
    message: "Can read your clipboard, which may include passwords, 2FA codes, and private messages",
  },
  {
    id: "ext_perm_clipboardWrite",
    permission: "clipboardWrite",
    weight: 25,
    message: "Can write to your clipboard, which can be abused to swap payment addresses or links",
  },
  {
    id: "ext_perm_scripting",
    permission: "scripting",
    weight: 35,
    message: "Can inject scripts into pages, which can read page content and interact with forms",
  },
];

function normalizeText(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.toLowerCase();
}

function purposeText(manifest: ManifestLike): string {
  return `${manifest.name ?? ""} ${manifest.description ?? ""}`.trim();
}

function allPermissionStrings(manifest: ManifestLike): string[] {
  const perms = [
    ...(manifest.permissions ?? []),
    ...(manifest.optional_permissions ?? []),
  ];
  return perms.filter((p) => typeof p === "string");
}

function allHostPatterns(manifest: ManifestLike): string[] {
  const fromHosts = [
    ...(manifest.host_permissions ?? []),
    ...(manifest.optional_host_permissions ?? []),
  ];
  const fromContentScripts =
    manifest.content_scripts?.flatMap((cs) => cs.matches ?? []) ?? [];

  return [...fromHosts, ...fromContentScripts].filter(
    (p) => typeof p === "string",
  );
}

function seemsToNeedPermission(purpose: string, permission: string): boolean {
  const text = normalizeText(purpose);
  if (!text) return true; // if no description, don't claim mismatch

  const keywordsByPermission: Record<string, string[]> = {
    tabs: ["tab", "tabs", "productivity", "session", "organize", "workspace"],
    cookies: ["cookie", "login", "auth", "session", "privacy", "tracking"],
    webRequest: ["request", "network", "proxy", "adblock", "block", "security"],
    history: ["history", "visited", "bookmark", "search", "recommend"],
    activeTab: ["tab", "page", "site", "current", "analyze", "scan"],
    clipboardRead: ["clipboard", "paste", "copy", "password", "security"],
    clipboardWrite: ["clipboard", "copy", "paste", "format"],
    scripting: ["inject", "script", "content", "page", "analyze", "scan"],
  };

  const keywords = keywordsByPermission[permission];
  if (!keywords) return true;
  return keywords.some((k) => text.includes(k));
}

export function analyzeExtensionManifest(manifest: ManifestLike): RiskSignal[] {
  const signals: RiskSignal[] = [];
  const permissions = allPermissionStrings(manifest);
  const hostPatterns = allHostPatterns(manifest);
  const purpose = purposeText(manifest);

  // Host permissions red flags
  const hasAllUrls =
    hostPatterns.includes("<all_urls>") || hostPatterns.includes("*://*/*");
  if (hasAllUrls) {
    signals.push({
      id: "ext_host_all_urls",
      message: "This extension can run on ALL websites (<all_urls>)",
      weight: 70,
      category: "Extension Host Access",
    });
  }

  // Background scripts / service worker
  if (manifest.background?.service_worker) {
    signals.push({
      id: "ext_background_service_worker",
      message: "Runs background code (service worker), which can perform work in the background",
      weight: 10,
      category: "Extension Background",
    });
  }
  if (manifest.background?.persistent === true) {
    signals.push({
      id: "ext_background_persistent",
      message: "Uses a persistent background page (higher tracking / always-on risk)",
      weight: 35,
      category: "Extension Background",
    });
  }

  // Permissions
  for (const def of DANGEROUS_PERMISSIONS) {
    if (!permissions.includes(def.permission)) continue;

    signals.push({
      id: def.id,
      message: def.message,
      weight: def.weight,
      category: "Extension Permission",
    });

    if (!seemsToNeedPermission(purpose, def.permission)) {
      signals.push({
        id: `${def.id}_mismatch`,
        message: `Permission “${def.permission}” may not match the extension’s stated purpose`,
        weight: 15,
        category: "Purpose Match",
      });
    }
  }

  return signals;
}
