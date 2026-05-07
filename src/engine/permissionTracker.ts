/**
 * Injects a script into the page to monitor and warn about permission requests via browser APIs.
 * Tracked permissions: Camera, Microphone, Location, Notifications, Clipboard, and Popups.
 */
export function initPermissionTracker() {
  // 1. Inject proxy script into the MAIN world to intercept native APIs
  // This is necessary because content scripts run in an isolated world and cannot 
  // directly see/modify objects in the page's JS context.
  const script = document.createElement('script');
  script.textContent = `
    (function() {
      const notify = (permission, action = 'requested', responseTime = null) => {
        window.postMessage({ 
          type: 'PG_PERMISSION_REQUEST', 
          permission, 
          action,
          origin: window.location.origin,
          responseTime
        }, '*');
      };

      const wrapPromise = (permission, originalFn, context) => {
        return function(...args) {
          const start = Date.now();
          notify(permission, 'requested');
          const p = originalFn.apply(context, args);
          if (p && typeof p.then === 'function') {
            p.then(() => notify(permission, 'allowed', Date.now() - start)).catch(() => {});
          }
          return p;
        };
      };

      // Camera & Microphone
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
        navigator.mediaDevices.getUserMedia = function(constraints) {
          const type = constraints?.video && constraints?.audio ? 'camera+microphone' : (constraints?.video ? 'camera' : 'microphone');
          const start = Date.now();
          notify(type, 'requested');
          const p = originalGetUserMedia(constraints);
          p.then(() => notify(type, 'allowed', Date.now() - start)).catch(() => {});
          return p;
        };
      }

      // Location
      if (navigator.geolocation) {
        const origGCP = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
        navigator.geolocation.getCurrentPosition = function(s, e, o) {
          const start = Date.now();
          notify('location', 'requested');
          return origGCP((pos) => { notify('location', 'allowed', Date.now() - start); if(s) s(pos); }, e, o);
        };
        const origWP = navigator.geolocation.watchPosition.bind(navigator.geolocation);
        navigator.geolocation.watchPosition = function(s, e, o) {
          const start = Date.now();
          notify('location', 'requested');
          return origWP((pos) => { notify('location', 'allowed', Date.now() - start); if(s) s(pos); }, e, o);
        };
      }

      // Notifications
      if (window.Notification && Notification.requestPermission) {
        Notification.requestPermission = wrapPromise('notifications', Notification.requestPermission, Notification);
      }

      // Clipboard
      if (navigator.clipboard) {
        navigator.clipboard.readText = wrapPromise('clipboard access', navigator.clipboard.readText, navigator.clipboard);
        navigator.clipboard.writeText = wrapPromise('clipboard access', navigator.clipboard.writeText, navigator.clipboard);
      }

      // Popups / Redirects
      const originalOpen = window.open.bind(window);
      window.open = function(url, target, features) {
        notify('popup', 'requested');
        const win = originalOpen(url, target, features);
        if (win) notify('popup', 'allowed');
        return win;
      };

      // Cookie Access Detection
      const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') || 
                                       Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
      if (originalCookieDescriptor && originalCookieDescriptor.get) {
        Object.defineProperty(document, 'cookie', {
          get: function() {
            notify('cookie read', 'allowed');
            return originalCookieDescriptor.get.call(this);
          },
          set: function(val) {
            return originalCookieDescriptor.set.call(this, val);
          }
        });
      }
    })();
  `;
  (document.head || document.documentElement).appendChild(script);
  script.remove();

  // 2. Listen for messages from the injected script
  window.addEventListener('message', (event) => {
    if (event.source !== window || event.data?.type !== 'PG_PERMISSION_REQUEST') return;
    
    const { permission, action, origin, responseTime } = event.data;
    
    // Send to background for persistent logging and analysis
    chrome.runtime.sendMessage({
      type: 'LOG_PERMISSION_REQUEST',
      payload: { permission, action, origin, timestamp: Date.now(), responseTime }
    });

    chrome.storage.local.get(['pg_mode'], (result) => {
      const mode = result.pg_mode || 'balanced';
      if (mode === 'silent' || action !== 'requested') return;

      const HIGH_RISK = ['camera', 'microphone', 'camera+microphone', 'location', 'clipboard access'];
      
      if (mode === 'strict') {
        const level = HIGH_RISK.includes(permission) ? 'CRITICAL' : 'CAUTION';
        showWarning(permission, level);
      } else if (mode === 'balanced') {
        if (HIGH_RISK.includes(permission)) {
          showWarning(permission, 'CRITICAL');
        }
      }
    });
  });
}

function showWarning(permission: string, level: 'INFO' | 'CAUTION' | 'CRITICAL') {
  const id = 'guardian-permission-alert';
  if (document.getElementById(id)) return;

  const colors = {
    CRITICAL: { bg: '#fff', border: '#b91c1c', icon: '🔴' },
    CAUTION: { bg: '#fff', border: '#b45309', icon: '🟡' },
    INFO: { bg: '#fff', border: '#3b82f6', icon: '🟢' }
  };
  const theme = colors[level] || colors.INFO;

  const div = document.createElement('div');
  div.id = id;
  div.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 2147483647;
    background: #ffffff;
    color: #111827;
    padding: 16px;
    border-radius: 12px;
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    border: 1px solid #e5e7eb;
    border-left: 5px solid ${theme.border};
    font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
    max-width: 320px;
    animation: pg-slide-in 0.3s ease-out;
  `;
  
  div.innerHTML = `
    <style>
      @keyframes pg-slide-in { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    </style>
    <div style="display:flex;align-items:center;gap:8px;font-weight:600;margin-bottom:8px;">
      <span style="font-size:18px;">${theme.icon}</span> ${level} Alert
    </div>
    <div style="font-size:14px;line-height:1.5;color:#374151;margin-bottom:12px;">
      This site is requesting <strong>${permission}</strong> access. Do you trust it?
    </div>
    <button id="pg-alert-dismiss" style="width:100%;background:#f3f4f6;border:none;padding:8px;border-radius:6px;cursor:pointer;font-weight:500;font-size:13px;transition:background 0.2s;">Dismiss</button>
  `;

  document.body.appendChild(div);
  const close = () => div.remove();
  document.getElementById('pg-alert-dismiss')?.addEventListener('click', close);
  // Auto-remove after 8 seconds
  setTimeout(close, 8000);
}