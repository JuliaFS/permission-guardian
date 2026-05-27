import type { RiskSignal } from "./types";

const DANGEROUS_PERMISSIONS: Array<{
  id: string;
  permission: string;
  weight: number;
  message: string;
}> = [
  // Add modern Chrome MV3 critical permissions
  {
    id: "ext_perm_proxy",
    permission: "proxy",
    weight: 90, // Very high risk
    message: "Can redirect your entire internet traffic through an external server. Risk of data theft.",
  },
  {
    id: "ext_perm_declarativeNetRequest",
    permission: "declarativeNetRequest",
    weight: 60,
    message: "Can observe, block, or modify network requests made by websites.",
  },
  {
    id: "ext_perm_declarativeNetRequestFeedback",
    permission: "declarativeNetRequestFeedback",
    weight: 60,
    message: "Can see and report which web requests you block or redirect.",
  },
  {
    id: "ext_perm_storage",
    permission: "storage",
    weight: 20,
    message: "Can store unlimited local data on your device.",
  }
];

// Keywords used to estimate whether a permission matches the extension's stated purpose.
const keywordsByPermission: Record<string, string[]> = {
  tabs: ["tab", "tabs", "productivity", "session", "organize", "workspace"],
  cookies: ["cookie", "login", "auth", "session", "privacy", "tracking"],
  webRequest: ["request", "network", "proxy", "adblock", "block", "security"],
  history: ["history", "visited", "bookmark", "search", "recommend"],
  activeTab: ["tab", "page", "site", "current", "analyze", "scan"],
  clipboardRead: ["clipboard", "paste", "copy", "password", "security"],
  clipboardWrite: ["clipboard", "copy", "paste", "format"],
  scripting: ["inject", "script", "content", "page", "analyze", "scan"],
  proxy: ["proxy", "vpn", "network", "traffic"],
  storage: ["storage", "local storage", "data", "cache", "save", "sync"],
  declarativeNetRequest: ["block", "adblock", "request", "filter"],
  declarativeNetRequestFeedback: ["block", "adblock", "request", "filter", "feedback", "report"]
};

type ManifestLike = {
  name?: string;
  description?: string;
  permissions?: string[];
  optional_permissions?: string[];
  host_permissions?: string[];
  background?: {
    service_worker?: string;
    persistent?: boolean;
  };
};

function allPermissionStrings(manifest: ManifestLike): string[] {
  const permissions = new Set<string>();
  const add = (items: unknown) => {
    if (!Array.isArray(items)) return;
    for (const item of items) {
      if (typeof item === "string") {
        permissions.add(item);
      }
    }
  };
  add(manifest.permissions);
  add(manifest.optional_permissions);
  return [...permissions];
}

function allHostPatterns(manifest: ManifestLike): string[] {
  const hosts = new Set<string>();
  const add = (items: unknown) => {
    if (!Array.isArray(items)) return;
    for (const item of items) {
      if (typeof item !== "string") continue;
      if (item === "<all_urls>" || item.includes("://") || item.includes("*") || item.startsWith("<")) {
        hosts.add(item);
      }
    }
  };
  add(manifest.host_permissions);
  add(manifest.permissions);
  add(manifest.optional_permissions);
  return [...hosts];
}

function purposeText(manifest: ManifestLike): string {
  return [manifest.name, manifest.description]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function isSelfManifest(manifest: ManifestLike): boolean {
  const text = purposeText(manifest);
  return text.includes("permission guardian") || text.includes("permissionguardian");
}

function seemsToNeedPermission(purpose: string, permission: string): boolean {
  const keywords = keywordsByPermission[permission] ?? [];
  const normalizedPurpose = purpose.toLowerCase();
  return keywords.some((keyword) => normalizedPurpose.includes(keyword));
}

export function analyzeExtensionManifest(manifest: ManifestLike): RiskSignal[] {
  if (isSelfManifest(manifest)) {
    return [
      {
        id: "ext_self_exclusion",
        message: "This is Permission Guardian itself. These permissions are used to observe and learn site behavior, not to guarantee instant protection for the user.",
        weight: 0,
        category: "Extension Permission",
        severity: "low",
      },
    ];
  }

  const signals: RiskSignal[] = [];
  const permissions = allPermissionStrings(manifest);
  const hostPatterns = allHostPatterns(manifest);
  const purpose = purposeText(manifest);

  const hasAllUrls = hostPatterns.includes("<all_urls>") || hostPatterns.includes("*://*/*");
  const hasActiveTab = permissions.includes("activeTab");

  // If the extension requests access to ALL sites, treat it as higher risk.
  if (hasAllUrls) {
    signals.push({
      id: "ext_host_all_urls",
      message: "This extension has access to every website you visit.",
      weight: 75,
      category: "Extension Host Access",
    });
  } else if (hasActiveTab) {
    // Educational: activeTab-only access is usually a safer pattern.
    signals.push({
      id: "ext_host_secure_activetab",
      message: "The extension only accesses sites after you explicitly click its icon. (Good security practice)",
      weight: 5, // Very low risk
      category: "Extension Host Access",
    });
  }

  // Background scripts / service worker (MV2 vs MV3 differences)
  if (manifest.background?.service_worker) {
    signals.push({
      id: "ext_background_service_worker",
      message: "Runs background code (Service Worker). It can perform tasks even when the panel is closed.",
      weight: 10,
      category: "Extension Background",
    });
  }
  
  // Persistent background page (MV2 legacy; higher tracking risk)
  if (manifest.background?.persistent === true) {
    signals.push({
      id: "ext_background_persistent",
      message: "Uses a persistent background page. Higher risk of real-time tracking.",
      weight: 40,
      category: "Extension Background",
    });
  }

  // Check dangerous permissions
  for (const def of DANGEROUS_PERMISSIONS) {
    if (!permissions.includes(def.permission)) continue;

    // If the extension also has <all_urls>, some permissions become even riskier.
    let finalWeight = def.weight;
    if (hasAllUrls && ["cookies", "scripting", "webRequest"].includes(def.permission)) {
      finalWeight += 15; // Higher risk because it applies across the entire web
    }

    signals.push({
      id: def.id,
      message: def.message,
      weight: Math.min(100, finalWeight),
      category: "Extension Permission",
    });

    // Purpose mismatch warning
    if (!seemsToNeedPermission(purpose, def.permission)) {
      signals.push({
        id: `${def.id}_mismatch`,
        message: `Warning: The permission "${def.permission}" does not match the stated purpose or extension name.`,
        weight: 25,
        category: "Purpose Match",
      });
    }
  }

  return signals;
}
