/**
 * Monitors the DOM for scripts or iframes injected by other extensions.
 */
export function initExtensionActivityTracker() {
  const runtime =
    (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime
  if (!runtime?.id) return

  function classifyInlineScript(node: HTMLElement) {
    const text = (node as HTMLScriptElement).textContent?.toLowerCase() ?? '';
    if (!text.trim()) return 'Inline script';

    if (text.includes('gtag(') || text.includes('google-analytics') || text.includes('analytics.js') || text.includes('dataLayer') || text.includes('ga(')) {
      return 'Inline script (analytics)';
    }
    if (text.includes('googletagmanager') || text.includes('gtm.js')) {
      return 'Inline script (tag manager)';
    }
    if (text.includes('fbq(') || text.includes('facebook') || text.includes('pixel')) {
      return 'Inline script (Facebook Pixel)';
    }
    if (text.includes('stripe') || text.includes('paypal') || text.includes('paymentrequest') || text.includes('checkout')) {
      return 'Inline script (payment)';
    }
    if (text.includes('document.cookie') || text.includes('navigator.sendbeacon') || text.includes('fingerprint') || text.includes('localstorage') || text.includes('sessionstorage') || text.includes('canvas') || text.includes('navigator.useragent')) {
      return 'Inline script (tracking)';
    }
    if (text.includes('recaptcha') || text.includes('grecaptcha')) {
      return 'Inline script (captcha)';
    }
    if (text.includes('youtube.com') || text.includes('vimeo.com') || text.includes('player')) {
      return 'Inline script (media embed)';
    }
    return 'Inline script';
  }

  const observer = new MutationObserver((mutations) => {
    try {
      // Check if runtime context is still valid before processing.
      // Accessing runtime.id can throw "Extension context invalidated" if the extension was reloaded.
      if (!runtime?.id) {
        observer.disconnect();
        return;
      }

      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node instanceof HTMLElement && (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME')) {
            const src = (node as any).src || classifyInlineScript(node);
            
            // Try to identify if it's from an extension
            const isExtension = src.startsWith('chrome-extension://') || src.startsWith('moz-extension://');
            
            try {
              runtime.sendMessage({
                type: 'LOG_EXTENSION_ACTIVITY',
                payload: {
                  type: isExtension ? 'extension_injection' : 'dynamic_injection',
                  detail: src,
                  timestamp: Date.now(),
                  origin: window.location.origin
                }
              });
            } catch (sendError) {
              console.debug('[PG] Failed to send extension activity message (context may be invalidated):', sendError);
            }
          }
        }
      }
    } catch (error) {
      console.debug('[PG] Error in extension activity observer:', error);
    }
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });
}
