export type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

export interface RiskSignal {
  id: string;
  message: string;
  weight: number;
  category: string;
}