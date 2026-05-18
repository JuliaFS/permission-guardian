export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface RiskSignal {
  id: string;
  message: string;
  weight: number;
  category: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

export interface InjectedSignal {
  signalId: string;
  action: string;
  timestamp: number;
}
