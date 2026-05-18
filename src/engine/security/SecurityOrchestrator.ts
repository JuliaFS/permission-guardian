import type { Signal, PermissionEvent } from './types';
import { SignalDetector } from './SignalDetector';
import { RiskEngine } from './RiskEngine';
import { BehaviorEngine } from './BehaviorEngine';

export class SecurityOrchestrator {
  private detector: SignalDetector;
  private risk: RiskEngine;
  private behavior: BehaviorEngine;

  constructor(
    detector?: SignalDetector,
    risk?: RiskEngine,
    behavior?: BehaviorEngine,
  ) {
    this.detector = detector ?? new SignalDetector();
    this.risk = risk ?? new RiskEngine();
    this.behavior = behavior ?? new BehaviorEngine();
  }

  async analyze(doc: Document, history?: PermissionEvent[]) {
    const pageSignals = this.detector.detectPageSignals(doc);
    const behaviorSignals = await this.behavior.analyze(history as PermissionEvent[]);

    const allSignals: Signal[] = [...pageSignals, ...behaviorSignals];

    const risk = this.risk.compute(allSignals);

    return {
      signals: allSignals,
      risk,
    };
  }
}
