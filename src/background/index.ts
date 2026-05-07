const runtime =
  (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime

runtime?.onInstalled?.addListener(() => {
  // eslint-disable-next-line no-console
  console.log('Permission Guardian installed')
})

type PermissionLog = {
  permission: string
  origin: string
  timestamp: number
  action: 'requested' | 'allowed'
  responseTime?: number
}

type InstallLog = {
  timestamp: number
  id: string
}

const action =
  (globalThis as any).chrome?.action ?? (globalThis as any).browser?.action
const tabs = (globalThis as any).chrome?.tabs ?? (globalThis as any).browser?.tabs
const storage = (globalThis as any).chrome?.storage?.local ?? (globalThis as any).browser?.storage?.local
const management = (globalThis as any).chrome?.management ?? (globalThis as any).browser?.management
const webRequest = (globalThis as any).chrome?.webRequest ?? (globalThis as any).browser?.webRequest

const LOG_STORAGE_KEY = 'pg_permission_history'
const INSTALL_LOG_KEY = 'pg_install_history'
const ACTIVITY_LOG_KEY = 'pg_extension_activity'
const LAST_USED_KEY = 'pg_extension_last_used'

runtime?.onMessage?.addListener((message: any) => {
  if (message.type === 'LOG_PERMISSION_REQUEST') {
    handlePermissionLog(message.payload)
  } else if (message.type === 'LOG_EXTENSION_ACTIVITY') {
    handleActivityLog(message.payload)
  } else if (message.type === 'GET_DASHBOARD_DATA') {
    return handleGetDashboardData().then(message.callback || (() => {}));
  } else if (message.type === 'REMOVE_EXTENSION') {
    management?.uninstall(message.id);
  } else if (message.type === 'CLEAR_SITE_DATA') {
    handleClearSiteData(message.origin);
  }
})

async function handleActivityLog(activity: any) {
  if (!storage) return
  const result = await storage.get([ACTIVITY_LOG_KEY, LAST_USED_KEY])
  const history = result[ACTIVITY_LOG_KEY] || []
  const lastUsed = result[LAST_USED_KEY] || {}

  history.push(activity)
  
  if (activity.extensionId) {
    lastUsed[activity.extensionId] = Date.now();
  }

  // Keep last 100 activities
  await storage.set({ 
    [ACTIVITY_LOG_KEY]: history.slice(-100),
    [LAST_USED_KEY]: lastUsed
  })
}

async function handleGetDashboardData() {
  if (!storage || !management) return null;

  const [extensions, data] = await Promise.all([
    management.getAll(),
    storage.get([LOG_STORAGE_KEY, ACTIVITY_LOG_KEY, LAST_USED_KEY])
  ]);

  const permHistory: PermissionLog[] = data[LOG_STORAGE_KEY] || [];
  const activity: any[] = data[ACTIVITY_LOG_KEY] || [];
  const lastUsed = data[LAST_USED_KEY] || {};

  // Group permissions by site
  const siteMap = new Map<string, Set<string>>();
  permHistory.filter(h => h.action === 'allowed').forEach(h => {
    if (!siteMap.has(h.origin)) siteMap.set(h.origin, new Set());
    siteMap.get(h.origin)?.add(h.permission);
  });

  const sitePermissions = Array.from(siteMap.entries()).map(([origin, perms]) => ({
    origin,
    permissions: Array.from(perms)
  }));

  // Map extensions to risk levels (simulated scoring)
  const extensionSummary = extensions.map((ext: any) => {
    const hasActivity = activity.some(a => a.extensionId === ext.id);
    return {
      id: ext.id,
      name: ext.name,
      enabled: ext.enabled,
      hasActivity,
      lastUsed: lastUsed[ext.id] || null,
      riskScore: ext.permissions.length * 10, // Basic heuristic
      version: ext.version
    };
  });

  return { extensionSummary, sitePermissions };
}

async function handleClearSiteData(origin: string) {
  if (!storage) return;
  const result = await storage.get([LOG_STORAGE_KEY]);
  const history: PermissionLog[] = result[LOG_STORAGE_KEY] || [];
  const filtered = history.filter(h => h.origin !== origin);
  await storage.set({ [LOG_STORAGE_KEY]: filtered });
}

management?.onInstalled?.addListener((info: any) => {
  handleInstallLog(info.id)
})

async function handleInstallLog(id: string) {
  if (!storage) return
  const result = await storage.get([INSTALL_LOG_KEY])
  const history: InstallLog[] = result[INSTALL_LOG_KEY] || []
  history.push({ timestamp: Date.now(), id })
  await storage.set({ [INSTALL_LOG_KEY]: history.filter(h => h.timestamp > Date.now() - 7 * 24 * 60 * 60 * 1000) })
}

// Advanced: Monitor network requests from extensions
webRequest?.onBeforeRequest.addListener(
  (details: any) => {
    if (details.initiator?.startsWith('chrome-extension://')) {
      const extensionId = details.initiator.split('//')[1].split('/')[0]
      handleActivityLog({
        type: 'network_request',
        extensionId,
        detail: `Request to: ${new URL(details.url).hostname}`,
        timestamp: Date.now(),
        origin: 'Background context'
      })
    }
  },
  { urls: ['<all_urls>'] }
)

async function handlePermissionLog(log: PermissionLog) {
  if (!storage) return

  const result = await storage.get([LOG_STORAGE_KEY])
  const history: PermissionLog[] = result[LOG_STORAGE_KEY] || []
  
  // Detect suspicious combos: Camera + microphone + unknown domain
  if (log.action === 'requested' && log.permission === 'camera+microphone') {
    const isKnown = history.some(h => h.origin === log.origin && h.action === 'allowed')
    if (!isKnown) {
      (globalThis as any).chrome?.notifications?.create({
        type: 'basic',
        iconUrl: '/icon128.png',
        title: '🚨 Suspicious Permission Request',
        message: `${log.origin} requested both camera and microphone but is not a previously trusted domain.`,
        priority: 2
      })
    }
  }

  history.push(log)
  
  // Keep only last week for tracking "this week" history
  const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
  const filteredHistory = history.filter((h: PermissionLog) => h.timestamp > oneWeekAgo)
  
  await storage.set({ [LOG_STORAGE_KEY]: filteredHistory })

  if (log.action === 'allowed') {
    const count = filteredHistory.filter((h: PermissionLog) => 
      h.origin === log.origin && h.permission === log.permission && h.action === 'allowed'
    ).length
    
    // Feature: History log info
    if (count >= 1) {
       // eslint-disable-next-line no-console
       console.log(`[Permission Guardian] History: You allowed ${log.permission} access to ${log.origin} ${count} times this week`)
    }
  } else {
    // eslint-disable-next-line no-console
    console.log(`[Permission Guardian] Tracking: ${log.permission} requested by ${log.origin}`)
  }
}

function badgeForLevel(level: string): { text: string; color: string } {
  switch (level) {
    case 'CRITICAL':
      return { text: 'CRT', color: '#7f1d1d' }
    case 'HIGH':
      return { text: 'HIGH', color: '#b91c1c' }
    case 'MEDIUM':
      return { text: 'MED', color: '#b45309' }
    case 'LOW':
    default:
      return { text: 'LOW', color: '#064e3b' }
  }
}