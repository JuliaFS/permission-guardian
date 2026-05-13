/**
 * educationalContent.ts - Maps technical signals to user-friendly explanations
 * Provides educational context for each permission/risk signal
 */

export interface EducationalItem {
  title: string;
  why: string[];
  advice: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  icon?: string;
}

export const EDUCATIONAL_MAP: Record<string, EducationalItem> = {
  // === Dark Patterns & Behavioral ===
  dark_pattern_urgency: {
    title: "Psychological Pressure (Dark Pattern)",
    severity: 'medium',
    why: [
      "Phrases like 'Only 2 left' or 'Expires in 10 minutes' are often artificially created.",
      "They're designed to bypass your rational decision-making and trigger impulse buying.",
      "Even if real, you're being manipulated by artificial scarcity."
    ],
    advice: [
      "Take your time. If it's truly on sale, it will likely be available later.",
      "Use your browser's back button. Many sites reset timers when you refresh.",
      "Search for the product on other sites to verify the 'urgency'."
    ],
    icon: "⏰"
  },

  high_third_party_load: {
    title: "Heavy Third-Party Script Loading",
    severity: 'low',
    why: [
      "The site is loading many scripts from external companies (trackers, advertisers, analytics).",
      "Each third-party script is an extra attack surface and privacy risk.",
      "Your browsing behavior is being collected and sold to advertisers."
    ],
    advice: [
      "Install an ad-blocker like uBlock Origin to reduce third-party scripts.",
      "Use Firefox with Enhanced Tracking Protection enabled.",
      "Consider using Privacy Badger to automatically block trackers."
    ],
    icon: "📊"
  },

  // === Canvas Fingerprinting ===
  canvas_fingerprint: {
    title: "Canvas Fingerprinting Attempt",
    severity: 'high',
    why: [
      "The site is trying to identify your computer by analyzing how your graphics card renders text.",
      "This creates a unique 'fingerprint' that survives cookie deletion and incognito mode.",
      "It's used for tracking you across the web without your permission or knowledge."
    ],
    advice: [
      "Enable Canvas fingerprinting protection in Firefox (privacy.resistFingerprinting = true).",
      "Use browser extensions like CanvasBlocker or Canvas Fingerprint Defender.",
      "Note: Chrome doesn't offer built-in protection. Consider switching to Firefox for better privacy."
    ],
    icon: "🖼️"
  },

  // === Clipboard Access ===
  clipboard_read: {
    title: "Clipboard Read Request",
    severity: 'critical',
    why: [
      "The site is trying to read everything you recently copied (passwords, API keys, private info).",
      "This could expose sensitive data like authentication tokens or confidential text.",
      "Browsers ask for permission, but many users click 'Allow' without thinking."
    ],
    advice: [
      "NEVER allow clipboard access unless you absolutely trust the site.",
      "Don't copy passwords or sensitive info before visiting untrusted websites.",
      "Use a password manager instead of copying passwords manually."
    ],
    icon: "📋"
  },

  clipboard_write: {
    title: "Clipboard Write Request",
    severity: 'medium',
    why: [
      "The site wants to place content on your clipboard (often tracking URLs or ads).",
      "You might accidentally share this modified content without knowing.",
      "It's less dangerous than read access, but still invasive."
    ],
    advice: [
      "Be aware that copied content might not be what you expect.",
      "Review clipboard contents (paste into a text editor) before sharing.",
      "Disable sites that abuse this feature."
    ],
    icon: "📄"
  },

  // === Motion Sensors ===
  motion_sensor_orientation: {
    title: "Motion Sensor Access (Orientation)",
    severity: 'medium',
    why: [
      "The site wants access to your device's gyroscope and accelerometer.",
      "Combined with other data, motion sensors can be used for fingerprinting.",
      "Some sites use this to detect if you're holding your phone in a specific way for ads."
    ],
    advice: [
      "Most legitimate sites don't need motion sensors.",
      "Decline access unless the site specifically needs it (e.g., VR, games).",
      "Mobile browsers may prompt when a site requests this; choose 'Block'."
    ],
    icon: "📱"
  },

  motion_sensor_motion: {
    title: "Motion Sensor Access (Acceleration)",
    severity: 'medium',
    why: [
      "The site wants continuous access to your device's motion data.",
      "This can be used to infer your location, detect when you're moving, or fingerprint your device.",
      "Constant collection drains your battery."
    ],
    advice: [
      "Only allow for apps that genuinely need it (fitness trackers, games).",
      "Check your mobile settings for which apps have sensor permissions.",
      "Revoke unnecessary permissions regularly."
    ],
    icon: "⚡"
  },

  // === Geolocation ===
  geolocation_request: {
    title: "Location Request (One-time)",
    severity: 'medium',
    why: [
      "The site wants to know your precise location using GPS or IP address.",
      "This reveals where you live, work, frequent, and travel.",
      "Marketing companies buy this data to target you with ads."
    ],
    advice: [
      "Only allow if the site truly needs it (maps, local restaurants, weather).",
      "Use approximate location (usually an option in browser settings).",
      "Disable location in your OS settings and only enable when needed."
    ],
    icon: "📍"
  },

  geolocation_watch: {
    title: "Continuous Location Tracking",
    severity: 'high',
    why: [
      "The site wants constant access to your location, not just once.",
      "This is highly invasive; advertisers pay for real-time tracking data.",
      "It reveals your exact movements, habits, and private locations."
    ],
    advice: [
      "NEVER allow continuous tracking. Use one-time location when possible.",
      "Check your browser's location permissions regularly and revoke unused ones.",
      "Use a VPN to mask your IP-based location."
    ],
    icon: "🗺️"
  },

  // === Camera & Microphone ===
  camera_request: {
    title: "Camera Access Request",
    severity: 'high',
    why: [
      "The site wants to activate your webcam.",
      "This is a huge privacy violation; someone could watch you without your knowledge.",
      "Malicious sites can spy on your video calls or personal moments."
    ],
    advice: [
      "Always cover your camera with a physical cover.",
      "Check browser permissions regularly for unexpected camera access.",
      "Use hardware kill switches if your laptop has them.",
      "Only allow camera for video calls on trusted sites (Zoom, Google Meet)."
    ],
    icon: "📹"
  },

  microphone_request: {
    title: "Microphone Access Request",
    severity: 'high',
    why: [
      "The site wants to record your audio.",
      "This captures your voice, private conversations, and sensitive information.",
      "It's often used to build audio profiles for targeted advertising."
    ],
    advice: [
      "Only allow for video conferencing on trusted sites.",
      "Regularly check browser permissions for unexpected mic access.",
      "Mute your mic in browser settings by default.",
      "Use physical muting if your device supports it."
    ],
    icon: "🎤"
  },

  // === Storage ===
  storage_write: {
    title: "Local Storage Write",
    severity: 'low',
    why: [
      "The site is saving data on your device (cookies, local storage).",
      "This is used to track you across sessions and remember your behavior.",
      "Combined with other data points, it enables personalized profiling."
    ],
    advice: [
      "Clear cookies and site data regularly (Browser Settings > Privacy).",
      "Use 'Delete cookies on exit' setting to auto-clear after browsing.",
      "Use private/incognito mode for sensitive browsing."
    ],
    icon: "💾"
  },

  storage_read: {
    title: "Local Storage Read",
    severity: 'low',
    why: [
      "The site is reading data it previously stored about you.",
      "This helps it track you and rebuild profiles about your interests.",
      "Combined with other trackers, this creates a detailed behavioral profile."
    ],
    advice: [
      "Understand that most sites track your behavior through stored data.",
      "Use storage isolation in Firefox (Enhanced Tracking Protection).",
      "Extensions like uBlock Origin can prevent many tracking attempts."
    ],
    icon: "📖"
  },

  // === Password ===
  password_field: {
    title: "Password Field Detected",
    severity: 'high',
    why: [
      "The site is asking for your password.",
      "Unencrypted password fields can be intercepted by hackers.",
      "Some malicious sites steal credentials to break into your other accounts."
    ],
    advice: [
      "Always check for HTTPS (🔒) in the address bar before entering passwords.",
      "Use a password manager to auto-fill passwords (most will warn you about spoofed sites).",
      "Never use the same password across multiple sites.",
      "Enable two-factor authentication (2FA) on important accounts."
    ],
    icon: "🔐"
  },

  // === Extension Risks ===
  ext_host_all_urls: {
    title: "Extension Runs on All Websites",
    severity: 'high',
    why: [
      "The extension can execute on every single site you visit.",
      "This includes banking sites, email, messaging apps, and personal work tools.",
      "A compromised update or small bug could affect your security everywhere."
    ],
    advice: [
      "Only install extensions from highly trusted developers.",
      "Prefer extensions scoped to specific sites rather than all URLs.",
      "Regularly review your installed extensions and remove unused ones.",
      "Check extension reviews and update history before installing."
    ],
    icon: "⚙️"
  },

  ext_permission_storage: {
    title: "Extension Storage Access",
    severity: 'medium',
    why: [
      "The extension can read and modify stored data.",
      "This includes your browsing history, saved passwords, and personal settings.",
      "A malicious extension could steal your data."
    ],
    advice: [
      "Only grant storage permissions to extensions you fully trust.",
      "Review what data each extension can access.",
      "Use developer tools to monitor extension activity."
    ],
    icon: "🗄️"
  }
};

/**
 * Gets educational content for a specific signal
 */
export function getEducationalContent(signalId: string): EducationalItem | null {
  return EDUCATIONAL_MAP[signalId] || null;
}

/**
 * Gets color class based on severity
 */
export function getSeverityColor(severity: string): string {
  const severityMap: Record<string, string> = {
    low: 'text-yellow-500',
    medium: 'text-orange-500',
    high: 'text-red-500',
    critical: 'text-red-700'
  };
  return severityMap[severity] || 'text-gray-500';
}

/**
 * Gets background class based on severity
 */
export function getSeverityBg(severity: string): string {
  const severityMap: Record<string, string> = {
    low: 'bg-yellow-100',
    medium: 'bg-orange-100',
    high: 'bg-red-100',
    critical: 'bg-red-200'
  };
  return severityMap[severity] || 'bg-gray-100';
}
