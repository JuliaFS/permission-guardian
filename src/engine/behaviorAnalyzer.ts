export interface BehavioralMetrics {
  score: number;
  habits: string[];
  suggestions: string[];
}

/**
 * Analyzes historical logs to identify risky user behaviors and calculate a security score.
 */
export async function analyzeBehavior(): Promise<BehavioralMetrics> {
  const storage = (globalThis as any).chrome?.storage?.local ?? (globalThis as any).browser?.storage?.local;
  if (!storage) return { score: 100, habits: [], suggestions: [] };

  const data = await storage.get(['pg_permission_history', 'pg_install_history']);
  const permHistory = data.pg_permission_history || [];
  const installHistory = data.pg_install_history || [];

  const habits: string[] = [];
  const suggestions: string[] = [];
  let score = 100;

  // 1. Analyze Permission Acceptance Rate (Always accepting)
  const requests = permHistory.filter((h: any) => h.action === 'requested').length;
  const allowed = permHistory.filter((h: any) => h.action === 'allowed').length;
  const allowRate = requests > 0 ? (allowed / requests) : 0;

  if (allowRate > 0.8 && requests > 5) {
    score -= 20;
    habits.push("You tend to accept permissions without reviewing them");
    suggestions.push("Be more selective. Not every site needs camera or location access.");
  }

  // 2. Analyze Reaction Speed (Clicking Allow too fast - under 1.2s)
  const fastClicks = permHistory.filter((h: any) => h.action === 'allowed' && h.responseTime && h.responseTime < 1200).length;
  if (fastClicks >= 2) {
    score -= 15;
    habits.push("Clicking 'Allow' too fast");
    suggestions.push("Take a moment to read permission requests before clicking Allow.");
  }

  // 3. Extension Install Frequency
  const oneDay = 24 * 60 * 60 * 1000;
  const recentInstalls = installHistory.filter((h: any) => Date.now() - h.timestamp < oneDay).length;
  if (recentInstalls > 3) {
    score -= 15;
    habits.push("Installing many extensions in a short period");
    suggestions.push("Only install extensions you actually need to reduce your attack surface.");
  }

  return { 
    score: Math.max(0, score), 
    habits, 
    suggestions 
  };
}