import type { Signal, PermissionEvent } from './types';
import { extensionApi } from '../../utils/extensionApi';

export class BehaviorEngine {
  async analyze(history?: PermissionEvent[]): Promise<Signal[]> {
    let hist = history;
    if (!hist) {
      const data = await extensionApi.getStorage(['pg_permission_history', 'pg_install_history']);
      hist = data?.pg_permission_history || [];
    }

    const signals: Signal[] = [];

    const overuse = this.permissionOveruse(hist as PermissionEvent[]);
    if (overuse) signals.push(overuse);

    const fastClicks = this.fastClickBehavior(hist as PermissionEvent[]);
    if (fastClicks) signals.push(fastClicks);

    return signals;
  }

  private permissionOveruse(history: PermissionEvent[]): Signal | null {
    const requests = history.filter(h => h.action === 'requested').length;
    const allowed = history.filter(h => h.action === 'allowed').length;

    if (requests < 5) return null;

    const rate = allowed / Math.max(1, requests);
    if (rate < 0.8) return null;

    return {
      id: 'permission_overuse',
      type: 'behavior',
      category: 'user_pattern',
      severity: 70,
      confidence: 0.7,
      source: 'runtime',
      metadata: { requests, allowed, rate },
      timestamp: Date.now(),
    };
  }

  private fastClickBehavior(history: PermissionEvent[]): Signal | null {
    const fastClicks = history.filter(h => h.action === 'allowed' && h.responseTime && h.responseTime < 1200).length;
    if (fastClicks < 2) return null;

    return {
      id: 'fast_clicks',
      type: 'behavior',
      category: 'user_pattern',
      severity: 60,
      confidence: 0.7,
      source: 'runtime',
      metadata: { fastClicks },
      timestamp: Date.now(),
    };
  }
}
