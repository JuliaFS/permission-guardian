import type { Signal } from './types';

export class RiskEngine {
  compute(signals: Signal[]) {
    if (!signals || signals.length === 0) {
      return { score: 100, level: this.getLevel(100) };
    }

    const weighted = signals.map(s => s.severity * s.confidence);

    const score = 100 - (weighted.reduce((a, b) => a + b, 0) / Math.max(1, signals.length));

    const bounded = Math.max(0, Math.min(100, Math.round(score)));

    return {
      score: bounded,
      level: this.getLevel(bounded),
    };
  }

  private getLevel(score: number) {
    if (score >= 70) return 'low-risk';
    if (score >= 30) return 'medium-risk';
    return 'high-risk';
  }
}
