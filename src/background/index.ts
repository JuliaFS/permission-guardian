const api = (globalThis as any).chrome ?? (globalThis as any).browser;

const WEEK_MS = 1000 * 60 * 60 * 24 * 7;
const MAX_PERMISSION_HISTORY = 1000;
const LOG_STORAGE_KEY = 'pg_permission_history';
const ACTIVITY_LOG_KEY = 'pg_extension_activity';
const LAST_USED_KEY = 'pg_extension_last_used';

// Хелпър за съхранение
async function getStorageValue<T>(key: string, fallback: T): Promise<T> {
  const result = await api.storage.local.get([key]);
  return result[key] ?? fallback;
}

async function setStorageValue(key: string, value: unknown) {
  await api.storage.local.set({ [key]: value });
}

// Автоматично инжектиране при зареждане на нов сайт
api.tabs.onUpdated.addListener((tabId: number, changeInfo: any, tab: any) => {
  if (changeInfo.status === 'complete' && tab.url && !isRestrictedUrl(tab.url)) {
    injectProxy(tabId);
  }
});

// Handle extension icon click to toggle the UI panel in the active tab
api.action.onClicked.addListener((tab: any) => {
  console.log('[PG] Icon clicked for tab:', tab.id);
  
  if (!tab.id) return;

  // If URL is missing (missing permissions), we proceed and let the content script fail if it's a restricted page
  if (tab.url && isRestrictedUrl(tab.url)) {
    api.notifications.create({
      type: 'basic',
      iconUrl: api.runtime.getURL('icons/icon48.png'),
      title: 'Permission Guardian',
      message: 'This extension cannot run on internal browser pages for security reasons.'
    });
    return;
  }

  api.tabs.sendMessage(tab.id, { type: 'PG_TOGGLE_PANEL' }).catch(async (err: any) => {
    console.warn('[PG] Content script not responding, attempting re-injection...', err);
    
    // If the message fails, the content script might have been orphaned by an extension reload.
    // We try to execute the toggle logic directly once.
    try {
      await api.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['assets/content-module.js'] // Ensure this matches your compiled content script path
      });
      api.tabs.sendMessage(tab.id, { type: 'PG_TOGGLE_PANEL' });
    } catch (reinjectErr) {
      console.error('[PG] Re-injection failed:', reinjectErr);
    }
  });
});

function isRestrictedUrl(url: string) {
  const restricted = ['chrome://', 'edge://', 'about:', 'chrome-extension://', 'chromewebstore.google.com'];
  return restricted.some(p => url.startsWith(p));
}

async function injectProxy(tabId: number) {
  try {
    await api.scripting.executeScript({
      target: { tabId },
      world: 'MAIN', // ВАЖНО: Трябва да е в MAIN, за да достъпим обекта navigator
      files: ['scripts/inject.js'] // Файлът, съдържащ кода за прихващане
    });
  } catch (e) {
    console.debug('[PG] Injection skipped:', e);
  }
}

// Слушател за съобщения от Content Script
api.runtime.onMessage.addListener((message: any, _sender: any, sendResponse: any) => {
  if (message.type === 'LOG_PERMISSION_REQUEST') {
    handlePermissionLog(message.payload);
  } else if (message.type === 'UPDATE_ACTIVITY' || message.type === 'LOG_EXTENSION_ACTIVITY') {
    handleActivityLog(message.payload);
  } else if (message.type === 'GET_DASHBOARD_DATA') {
    handleGetDashboardData().then(sendResponse);
    return true; // async
  }
});

async function handlePermissionLog(log: any) {
  const history = await getStorageValue<any[]>(LOG_STORAGE_KEY, []);
  
  // Throttling for high-frequency signals (Canvas, Storage reads, etc.)
  const highFrequencySignals = [
    'canvas_fingerprint',
    'storage_read',
    'storage_write',
    'clipboard_read'
  ];

  if (highFrequencySignals.includes(log.permission)) {
    const lastLog = history.reverse().find(i => i.origin === log.origin && i.permission === log.permission);
    if (lastLog && Date.now() - lastLog.timestamp < 5000) return; // max once per 5 seconds
  }

  // Legacy throttling for cookie reads
  if (log.permission === 'cookie read') {
    const lastLog = history.reverse().find(i => i.origin === log.origin && i.permission === 'cookie read');
    if (lastLog && Date.now() - lastLog.timestamp < 10000) return; // макс веднъж на 10 сек
  }

  history.push({ ...log, timestamp: Date.now() });
  
  const filtered = history
    .filter(item => item.timestamp > Date.now() - WEEK_MS)
    .slice(-MAX_PERMISSION_HISTORY);

  await setStorageValue(LOG_STORAGE_KEY, filtered);
}

async function handleActivityLog(activity: any) {
  const logs = await getStorageValue<any[]>(ACTIVITY_LOG_KEY, []);
  const now = Date.now();
  
  logs.push({ ...activity, timestamp: now });
  
  const filtered = logs
    .filter(item => item.timestamp > now - WEEK_MS)
    .slice(-MAX_PERMISSION_HISTORY);

  await Promise.all([
    setStorageValue(ACTIVITY_LOG_KEY, filtered),
    setStorageValue(LAST_USED_KEY, now)
  ]);
}

async function handleGetDashboardData() {
  const [history, activity, lastUsed, extensions] = await Promise.all([
    getStorageValue(LOG_STORAGE_KEY, []),
    getStorageValue(ACTIVITY_LOG_KEY, []),
    getStorageValue(LAST_USED_KEY, null),
    api.management.getAll()
  ]);
  return { history, activity, lastUsed, extensions };
}
