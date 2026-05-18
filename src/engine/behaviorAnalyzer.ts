import { extensionApi } from "../utils/extensionApi";

export interface BehavioralSignal {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  action?: string;
}

export interface BehavioralMetrics {
  // When we don't have enough data yet, score is null so the UI can show "Not enough data"
  score: number | null;
  habits: string[];
  suggestions: string[];
  siteSignals?: BehavioralSignal[]; // New signals from the current site
}

/**
 * Analyzes both the user's historical data and the behavior of the current site.
 */
export async function analyzeBehavior(): Promise<BehavioralMetrics> {
  // Initialize results
  const habits: string[] = [];
  const suggestions: string[] = [];
  let score = 100;

  // --- LOGIC A: Real-time site analysis (New part) ---
  const siteSignals = analyzeCurrentSite();
  siteSignals.forEach(signal => {
    if (signal.severity === 'medium') score -= 10;
    if (signal.severity === 'low') score -= 5;
    habits.push(signal.description);
    // Adding a specific suggestion for each site signal
    if (signal.id === 'dark_pattern_urgency') suggestions.push("Don't be misled by countdown timers or 'last item left' labels.");
    if (signal.id === 'high_third_party_load') suggestions.push("Use an AdBlocker to limit third-party tracking.");
  });

  // --- LOGIC B: Analysis of user historical data (Your logic) ---
  let hasHistoryData = false;
  if (extensionApi.isAvailable) {
    const data = await extensionApi.getStorage(['pg_permission_history', 'pg_install_history']);
    const permHistory = data.pg_permission_history || [];
    const installHistory = data.pg_install_history || [];
    hasHistoryData = permHistory.length > 0 || installHistory.length > 0;

    // 1. Acceptance rate
    const requests = permHistory.filter((h: any) => h.action === 'requested').length;
    const allowed = permHistory.filter((h: any) => h.action === 'allowed').length;
    const allowRate = requests > 0 ? (allowed / requests) : 0;

    if (allowRate > 0.8 && requests > 5) {
      score -= 20;
      habits.push("You accept almost all access requests.");
      suggestions.push("Be more critical. Not every site needs camera or location access.");
    }

    // 2. Reaction speed (under 1.2 sec)
    const fastClicks = permHistory.filter((h: any) => h.action === 'allowed' && h.responseTime && h.responseTime < 1200).length;
    if (fastClicks >= 2) {
      score -= 15;
      habits.push("You click 'Allow' too quickly.");
      suggestions.push("Take a second to read exactly what the site is requesting.");
    }

    // 3. Installation frequency
    const oneDay = 24 * 60 * 60 * 1000;
    const recentInstalls = installHistory.filter((h: any) => Date.now() - h.timestamp < oneDay).length;
    if (recentInstalls > 3) {
      score -= 15;
      habits.push("You have installed many extensions at once.");
      suggestions.push("Remove extensions that you haven't used in the last month.");
    }
  }

  // If we have no behavioral history and no real-time site signals, don't claim "100/100".
  if (!hasHistoryData && siteSignals.length === 0) {
    return {
      score: null,
      habits: [],
      suggestions: ["No behavior data collected yet. Browse normally and open the panel again later."],
      siteSignals,
    };
  }

  return { 
    score: Math.max(0, score), 
    habits, 
    suggestions,
    siteSignals 
  };
}

/**
 * Helper function to analyze the current DOM (Dark Patterns & Scripts)
 */
function analyzeCurrentSite() {
  const signals = [];
  
  // 1. Check for Dark Patterns (Artificial urgency)
  const urgencyRegex = /(last chance|only \d left|remaining|last opportunity|expires in)/i;
  const hasUrgency = urgencyRegex.test(document.body.innerText);
  
  if (hasUrgency) {
    signals.push({ 
      id: 'dark_pattern_urgency', 
      severity: 'medium' as const, 
      description: 'The site uses urgency tricks (Dark Patterns).' 
    });
  }

  // 2. Check for third-party load (Trackers)
  const scripts = Array.from(document.scripts);
  const currentHost = window.location.hostname;
  const thirdPartyScripts = scripts.filter(s => s.src && !s.src.includes(currentHost));

  if (thirdPartyScripts.length > 15) {
    signals.push({ 
      id: 'high_third_party_load', 
      severity: 'low' as const, 
      description: `Detected ${thirdPartyScripts.length} external scripts (possible tracking).` 
    });
  }

  return signals;
}
