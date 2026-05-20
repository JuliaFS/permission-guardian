/**
 * inject.ts - Runs in the MAIN world (before content script)
 * Intercepts Canvas Fingerprinting, Clipboard access, and Motion sensors
 * Communicates via window events to the Content Script (ISOLATED world)
 */

(function () {
  // Helper function to dispatch events to Content Script
  const dispatch = (signalId: string, action: string, detail?: Record<string, unknown>) => {
    window.dispatchEvent(
      new CustomEvent('PG_SIGNAL_EVENT', {
        detail: {
          signalId,
          action,
          timestamp: Date.now(),
          origin: window.location?.origin ?? '',
          ...detail,
        },
      }),
    );
  };

  function detectCardDataInString(text: string): boolean {
    const cardNumberRegex = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/;
    const cvcRegex = /"cvc"\s*:\s*"\d{3}"|"cvv"\s*:\s*"\d{3}"|\bcvc=\d{3}\b|\bcvv=\d{3}\b/i;
    return cardNumberRegex.test(text) || cvcRegex.test(text);
  }

  function extractBodyAsString(body: any): string | null {
    if (typeof body === 'string') return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof FormData) {
      const entries = Array.from(body.entries()).map(([key, value]) => `${key}=${value}`);
      return entries.join('&');
    }
    if (body instanceof Blob) {
      return null;
    }
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
      try {
        return new TextDecoder().decode(body as ArrayBufferLike);
      } catch {
        return null;
      }
    }
    return null;
  }

  function triggerCardLeakAlert(url: string) {
    dispatch('card_data_exfiltration', 'detected', { url });
  }

  // === 1. Canvas Fingerprinting Interception ===
  const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(type?: string, encoderOptions?: any) {
    dispatch('canvas_fingerprint', 'requested');
    return originalToDataURL.call(this, type, encoderOptions);
  };

  const originalToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function(callback: BlobCallback, type?: string, quality?: any) {
    dispatch('canvas_fingerprint', 'requested');
    return originalToBlob.call(this, callback, type, quality);
  };

  // === 2. Network Exfiltration Interception ===
  const originalFetch = window.fetch;
  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const body = init?.body ?? (typeof input !== 'string' && input instanceof Request ? input.body : null);
    const bodyString = extractBodyAsString(body);

    if (bodyString && detectCardDataInString(bodyString)) {
      triggerCardLeakAlert(url);
    }

    return originalFetch.apply(this, arguments as any);
  };

  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function () {
    try {
      const url = arguments[1];
      (this as any)._pgRequestUrl = typeof url === 'string' ? url : url?.toString?.() ?? '';
    } catch {
      (this as any)._pgRequestUrl = '';
    }
    return originalXHROpen.apply(this, arguments as any);
  };

  XMLHttpRequest.prototype.send = function (body?: Document | BodyInit | null) {
    const requestUrl = (this as any)._pgRequestUrl || window.location.href;
    const bodyString = extractBodyAsString(body);
    if (bodyString && detectCardDataInString(bodyString)) {
      triggerCardLeakAlert(requestUrl);
    }
    return originalXHRSend.apply(this, arguments as any);
  };

  // === 3. Clipboard Access Interception ===
  if (navigator.clipboard) {
    const originalReadText = navigator.clipboard.readText;
    navigator.clipboard.readText = async function() {
      dispatch('clipboard_read', 'requested');
      return originalReadText.call(navigator.clipboard);
    };

    const originalWriteText = navigator.clipboard.writeText;
    navigator.clipboard.writeText = async function(text: string) {
      dispatch('clipboard_write', 'requested');
      return originalWriteText.call(navigator.clipboard, text);
    };

    const originalRead = navigator.clipboard.read;
    navigator.clipboard.read = async function() {
      dispatch('clipboard_read', 'requested');
      return originalRead.call(navigator.clipboard);
    };
  }

  // === 3. Motion & Orientation Sensor Interception ===
  window.addEventListener('deviceorientation', () => {
    dispatch('motion_sensor_orientation', 'allowed');
  }, { once: true });

  window.addEventListener('devicemotion', () => {
    dispatch('motion_sensor_motion', 'allowed');
  }, { once: true });

  window.addEventListener('deviceorientationabsolute', () => {
    dispatch('motion_sensor_absolute', 'allowed');
  }, { once: true });

  // === 4. Geolocation Interception ===
  if (navigator.geolocation) {
    const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition;
    navigator.geolocation.getCurrentPosition = function(successCallback: PositionCallback, errorCallback?: PositionErrorCallback | null, options?: PositionOptions) {
      dispatch('geolocation_request', 'requested');
      return originalGetCurrentPosition.call(navigator.geolocation, successCallback, errorCallback, options);
    };

    const originalWatchPosition = navigator.geolocation.watchPosition;
    navigator.geolocation.watchPosition = function(successCallback: PositionCallback, errorCallback?: PositionErrorCallback | null, options?: PositionOptions) {
      dispatch('geolocation_watch', 'requested');
      return originalWatchPosition.call(navigator.geolocation, successCallback, errorCallback, options);
    };
  }

  // === 5. Microphone/Camera Access (via getUserMedia) ===
  if (navigator.mediaDevices) {
    const originalGetUserMedia = navigator.mediaDevices.getUserMedia;
    navigator.mediaDevices.getUserMedia = async function(constraints: MediaStreamConstraints) {
      if (constraints.audio) {
        dispatch('microphone_request', 'requested');
      }
      if (constraints.video) {
        dispatch('camera_request', 'requested');
      }
      return originalGetUserMedia.call(navigator.mediaDevices, constraints);
    };
  }

  // === 6. Local Storage & IndexedDB Monitoring ===
  const originalSetItem = Storage.prototype.setItem;
  Storage.prototype.setItem = function(key: string, value: string) {
    dispatch('storage_write', 'requested');
    return originalSetItem.call(this, key, value);
  };

  const originalGetItem = Storage.prototype.getItem;
  Storage.prototype.getItem = function(key: string) {
    dispatch('storage_read', 'requested');
    return originalGetItem.call(this, key);
  };
})();
