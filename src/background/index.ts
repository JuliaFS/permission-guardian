// background/index.ts

const browserApi = (globalThis as any).chrome ?? (globalThis as any).browser

const runtime = browserApi?.runtime
const storage = browserApi?.storage?.local
const management = browserApi?.management
const webRequest = browserApi?.webRequest
const action = browserApi?.action
const tabs = browserApi?.tabs
const scripting = browserApi?.scripting
const notifications = browserApi?.notifications

const WEEK_MS = 1000 * 60 * 60 * 24 * 7
const MAX_PERMISSION_HISTORY = 1000

const LOG_STORAGE_KEY = 'pg_permission_history'
const INSTALL_LOG_KEY = 'pg_install_history'
const ACTIVITY_LOG_KEY = 'pg_extension_activity'
const LAST_USED_KEY = 'pg_extension_last_used'

type PermissionAction = 'requested' | 'allowed'

interface PermissionLog {
  permission: string
  origin: string
  timestamp: number
  action: PermissionAction
  responseTime?: number
}

interface InstallLog {
  timestamp: number
  id: string
}

interface ExtensionActivity {
  type: string
  extensionId?: string
  detail?: string
  timestamp: number
  origin?: string
}

const restrictedProtocols = [
  'chrome://',
  'chrome-extension://',
  'edge://',
  'about:',
  'view-source:',
  'moz-extension://',
  'devtools://',
]

const notificationCooldown = new Map<string, number>()

function canNotify(key: string, cooldownMs = 30000) {
  const now = Date.now()
  const last = notificationCooldown.get(key) ?? 0

  if (now - last < cooldownMs) {
    return false
  }

  notificationCooldown.set(key, now)
  return true
}

function isRestrictedTabUrl(url: unknown) {
  if (typeof url !== 'string') return true

  const lower = url.toLowerCase()

  if (restrictedProtocols.some(protocol => lower.startsWith(protocol))) {
    return true
  }

  if (lower.startsWith('https://chrome.google.com/webstore')) {
    return true
  }

  if (lower.startsWith('https://chromewebstore.google.com')) {
    return true
  }

  return false
}

async function getStorageValue<T>(key: string, fallback: T): Promise<T> {
  try {
    if (!storage) return fallback

    const result = await storage.get([key])

    return result[key] ?? fallback
  } catch (error) {
    console.error(`[Permission Guardian] Failed reading ${key}`, error)
    return fallback
  }
}

async function setStorageValue(key: string, value: unknown) {
  try {
    if (!storage) return

    await storage.set({
      [key]: value,
    })
  } catch (error) {
    console.error(`[Permission Guardian] Failed writing ${key}`, error)
  }
}

function showNotification(title: string, message: string, priority = 0) {
  const iconUrl =
    runtime?.getURL?.('icons/icon128.png') ?? 'icons/icon128.png'

  notifications?.create?.({
    type: 'basic',
    iconUrl,
    title,
    message,
    priority,
  })
}

function showNotAccessibleNotice(url?: string) {
  const message =
    url && isRestrictedTabUrl(url)
      ? 'This is a restricted browser page. Permission Guardian cannot run here.'
      : 'Permission Guardian cannot access this tab.'

  showNotification('Permission Guardian', message)
}

runtime?.onInstalled?.addListener(() => {
  console.log('[Permission Guardian] Installed')
})

action?.onClicked?.addListener((tab: any) => {
  const tabId = tab?.id

  if (typeof tabId !== 'number') return

  const url = tab?.url

  if (isRestrictedTabUrl(url)) {
    showNotAccessibleNotice(url)
    return
  }

  tabs?.sendMessage?.(
    tabId,
    {
      type: 'PG_TOGGLE_PANEL',
    },
    () => {
      const lastError = runtime?.lastError

      if (lastError) {
        showNotAccessibleNotice(url)
      }
    },
  )
})

function permissionProxyMain() {
  const INSTALL_FLAG = Symbol.for('pg.permission.proxy')

  const w = window as any

  if (w[INSTALL_FLAG]) return

  w[INSTALL_FLAG] = true

  const notify = (
    permission: string,
    action: 'requested' | 'allowed' = 'requested',
    responseTime: number | null = null,
  ) => {
    window.postMessage(
      {
        type: 'PG_PERMISSION_REQUEST',
        permission,
        action,
        origin: window.location.origin,
        responseTime,
      },
      '*',
    )
  }

  const wrapPromise = (
    permission: string,
    originalFn: (...args: any[]) => Promise<any>,
    context: any,
  ) => {
    return function (...args: any[]) {
      const start = Date.now()

      notify(permission, 'requested')

      const promise = originalFn.apply(context, args)

      if (promise && typeof promise.then === 'function') {
        promise
          .then(() => {
            notify(permission, 'allowed', Date.now() - start)
          })
          .catch((error: unknown) => {
            console.debug(
              '[Permission Guardian] Permission denied',
              error,
            )
          })
      }

      return promise
    }
  }

  if (navigator.mediaDevices?.getUserMedia) {
    const originalGetUserMedia =
      navigator.mediaDevices.getUserMedia.bind(
        navigator.mediaDevices,
      )

    Object.defineProperty(navigator.mediaDevices, 'getUserMedia', {
      configurable: true,
      writable: true,
      value(constraints: MediaStreamConstraints) {
        const type =
          constraints.video && constraints.audio
            ? 'camera+microphone'
            : constraints.video
              ? 'camera'
              : 'microphone'

        const start = Date.now()

        notify(type, 'requested')

        const promise = originalGetUserMedia(constraints)

        promise
          .then(() => {
            notify(type, 'allowed', Date.now() - start)
          })
          .catch((error: unknown) => {
            console.debug(error)
          })

        return promise
      },
    })
  }

  if (navigator.geolocation) {
    const geo = navigator.geolocation

    const originalGetCurrentPosition =
      geo.getCurrentPosition.bind(geo)

    geo.getCurrentPosition = function (
      success,
      error,
      options,
    ) {
      const start = Date.now()

      notify('location', 'requested')

      return originalGetCurrentPosition(
        position => {
          notify('location', 'allowed', Date.now() - start)

          success(position)
        },
        error,
        options,
      )
    }

    const originalWatchPosition =
      geo.watchPosition.bind(geo)

    geo.watchPosition = function (
      success,
      error,
      options,
    ) {
      const start = Date.now()

      notify('location', 'requested')

      return originalWatchPosition(
        position => {
          notify('location', 'allowed', Date.now() - start)

          success(position)
        },
        error,
        options,
      )
    }
  }

  if (
    'Notification' in window &&
    window.Notification.requestPermission
  ) {
    window.Notification.requestPermission = wrapPromise(
      'notifications',
      window.Notification.requestPermission,
      window.Notification,
    )
  }

  if (navigator.clipboard) {
    const clipboard = navigator.clipboard as any

    if (clipboard.readText) {
      clipboard.readText = wrapPromise(
        'clipboard access',
        clipboard.readText,
        clipboard,
      )
    }

    if (clipboard.writeText) {
      clipboard.writeText = wrapPromise(
        'clipboard access',
        clipboard.writeText,
        clipboard,
      )
    }
  }

  if (window.open) {
    const originalOpen = window.open.bind(window)

    window.open = function (
      url?: string | URL,
      target?: string,
      features?: string,
    ) {
      notify('popup', 'requested')

      const popup = originalOpen(
        url as any,
        target,
        features,
      )

      if (popup) {
        notify('popup', 'allowed')
      }

      return popup
    }
  }

  const cookieDescriptor =
    Object.getOwnPropertyDescriptor(
      Document.prototype,
      'cookie',
    ) ??
    Object.getOwnPropertyDescriptor(
      HTMLDocument.prototype,
      'cookie',
    )

  if (cookieDescriptor?.get) {
    Object.defineProperty(Document.prototype, 'cookie', {
      configurable: true,

      get() {
        notify('cookie read', 'allowed')

        return cookieDescriptor.get?.call(this)
      },

      set(value: string) {
        return cookieDescriptor.set?.call(this, value)
      },
    })
  }
}

runtime?.onMessage?.addListener(
  (
    message: any,
    sender: any,
    sendResponse: (response?: any) => void,
  ) => {
    if (message.type === 'LOG_PERMISSION_REQUEST') {
      handlePermissionLog(message.payload)
    }

    else if (message.type === 'LOG_EXTENSION_ACTIVITY') {
      handleActivityLog(message.payload)
    }

    else if (message.type === 'PG_INJECT_PERMISSION_PROXY') {
      injectPermissionProxy(sender)
    }

    else if (message.type === 'GET_DASHBOARD_DATA') {
      handleGetDashboardData().then(sendResponse)
      return true
    }

    else if (message.type === 'REMOVE_EXTENSION') {
      management?.uninstall?.(message.id)
    }

    else if (message.type === 'CLEAR_SITE_DATA') {
      handleClearSiteData(message.origin)
    }
  },
)

async function injectPermissionProxy(sender: any) {
  const tabId = sender?.tab?.id
  const tabUrl = sender?.tab?.url

  if (typeof tabId !== 'number') return

  if (isRestrictedTabUrl(tabUrl)) {
    showNotAccessibleNotice(tabUrl)
    return
  }

  try {
    const injectOptions: any = {
      target: { tabId },
      func: permissionProxyMain,
    }

    if (browserApi?.chrome) {
      injectOptions.world = 'MAIN'
    }

    await scripting?.executeScript?.(injectOptions)
  } catch (error) {
    console.error(error)
    showNotAccessibleNotice(tabUrl)
  }
}

async function handleActivityLog(
  activity: ExtensionActivity,
) {
  const history = await getStorageValue<ExtensionActivity[]>(
    ACTIVITY_LOG_KEY,
    [],
  )

  const lastUsed = await getStorageValue<
    Record<string, number>
  >(LAST_USED_KEY, {})

  history.push(activity)

  if (history.length > 100) {
    history.splice(0, history.length - 100)
  }

  if (activity.extensionId) {
    lastUsed[activity.extensionId] = Date.now()
  }

  await setStorageValue(ACTIVITY_LOG_KEY, history)
  await setStorageValue(LAST_USED_KEY, lastUsed)
}

async function handlePermissionLog(log: PermissionLog) {
  const history = await getStorageValue<PermissionLog[]>(
    LOG_STORAGE_KEY,
    [],
  )

  if (
    log.action === 'requested' &&
    log.permission === 'camera+microphone'
  ) {
    const isKnown = history.some(
      item =>
        item.origin === log.origin &&
        item.action === 'allowed',
    )

    if (!isKnown && canNotify(log.origin)) {
      showNotification(
        '🚨 Suspicious Permission Request',
        `${log.origin} requested camera and microphone access.`,
        2,
      )
    }
  }

  history.push(log)

  const oneWeekAgo = Date.now() - WEEK_MS

  const filteredHistory = history
    .filter(item => item.timestamp > oneWeekAgo)
    .slice(-MAX_PERMISSION_HISTORY)

  await setStorageValue(
    LOG_STORAGE_KEY,
    filteredHistory,
  )

  if (log.action === 'allowed') {
    const count = filteredHistory.filter(
      item =>
        item.origin === log.origin &&
        item.permission === log.permission &&
        item.action === 'allowed',
    ).length

    console.log(
      `[Permission Guardian] ${log.origin} allowed ${log.permission} ${count} times this week`,
    )
  } else {
    console.log(
      `[Permission Guardian] ${log.permission} requested by ${log.origin}`,
    )
  }
}

async function handleInstallLog(id: string) {
  const history = await getStorageValue<InstallLog[]>(
    INSTALL_LOG_KEY,
    [],
  )

  history.push({
    timestamp: Date.now(),
    id,
  })

  const filtered = history.filter(
    item => item.timestamp > Date.now() - WEEK_MS,
  )

  await setStorageValue(INSTALL_LOG_KEY, filtered)
}

management?.onInstalled?.addListener(
  (info: any) => {
    handleInstallLog(info.id)
  },
)

webRequest?.onBeforeRequest.addListener(
  (details: any) => {
    if (
      typeof details.initiator === 'string' &&
      details.initiator.startsWith(
        'chrome-extension://',
      )
    ) {
      const extensionId =
        details.initiator.split('//')[1]?.split('/')[0]

      let hostname = 'unknown'

      try {
        hostname = new URL(details.url).hostname
      } catch {}

      handleActivityLog({
        type: 'network_request',
        extensionId,
        detail: `Request to: ${hostname}`,
        timestamp: Date.now(),
        origin: 'Background context',
      })
    }
  },
  {
    urls: ['<all_urls>'],
  },
)

async function handleGetDashboardData() {
  if (!management) return null

  const [extensions, permissionHistory, activity, lastUsed] =
    await Promise.all([
      management.getAll(),
      getStorageValue<PermissionLog[]>(
        LOG_STORAGE_KEY,
        [],
      ),
      getStorageValue<ExtensionActivity[]>(
        ACTIVITY_LOG_KEY,
        [],
      ),
      getStorageValue<Record<string, number>>(
        LAST_USED_KEY,
        {},
      ),
    ])

  const siteMap = new Map<string, Set<string>>()

  permissionHistory
    .filter(item => item.action === 'allowed')
    .forEach(item => {
      if (!siteMap.has(item.origin)) {
        siteMap.set(item.origin, new Set())
      }

      siteMap.get(item.origin)?.add(item.permission)
    })

  const sitePermissions = Array.from(
    siteMap.entries(),
  ).map(([origin, permissions]) => ({
    origin,
    permissions: Array.from(permissions),
  }))

  const extensionSummary = extensions.map(
    (extension: any) => {
      const hasActivity = activity.some(
        item => item.extensionId === extension.id,
      )

      return {
        id: extension.id,
        name: extension.name,
        enabled: extension.enabled,
        version: extension.version,
        hasActivity,
        lastUsed: lastUsed[extension.id] ?? null,
        riskScore:
          (extension.permissions?.length ?? 0) * 10,
      }
    },
  )

  return {
    extensionSummary,
    sitePermissions,
  }
}

async function handleClearSiteData(origin: string) {
  const history = await getStorageValue<PermissionLog[]>(
    LOG_STORAGE_KEY,
    [],
  )

  const filtered = history.filter(
    item => item.origin !== origin,
  )

  await setStorageValue(LOG_STORAGE_KEY, filtered)
}