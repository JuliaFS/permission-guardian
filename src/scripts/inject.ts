/**
 * inject.ts - Runs in the MAIN world (before content script)
 * Intercepts Canvas Fingerprinting, Clipboard access, and Motion sensors
 * Communicates via window events to the Content Script (ISOLATED world)
 */

(function () {
  // Helper function to dispatch events to Content Script
  const dispatch = (signalId: string, action: string) => {
    window.dispatchEvent(
      new CustomEvent('PG_SIGNAL_EVENT', {
        detail: { signalId, action, timestamp: Date.now() }
      })
    );
  };

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

  // === 2. Clipboard Access Interception ===
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
