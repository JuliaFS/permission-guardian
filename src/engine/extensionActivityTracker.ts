/**
 * Monitors the DOM for scripts or iframes injected by other extensions.
 */
export function initExtensionActivityTracker() {
  const runtime =
    (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime
  if (!runtime?.sendMessage) return

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node instanceof HTMLElement && (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME')) {
          const src = (node as any).src || 'Inline script';
          
          // Try to identify if it's from an extension
          const isExtension = src.startsWith('chrome-extension://') || src.startsWith('moz-extension://');
          
          runtime.sendMessage({
            type: 'LOG_EXTENSION_ACTIVITY',
            payload: {
              type: isExtension ? 'extension_injection' : 'dynamic_injection',
              detail: src,
              timestamp: Date.now(),
              origin: window.location.origin
            }
          });
        }
      }
    }
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });
}
