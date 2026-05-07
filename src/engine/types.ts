export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface RiskSignal {
  id: string;
  message: string;
  weight: number;
  category: string;
}
