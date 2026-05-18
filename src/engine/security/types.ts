export type Signal = {
  id: string;
  type: 'page' | 'extension' | 'behavior' | 'network';
  category: string;
  severity: number; // 0-100
  confidence: number; // 0-1
  source: 'dom' | 'manifest' | 'runtime' | 'network';
  metadata?: Record<string, any>;
  timestamp: number;
}

export type PermissionEvent = {
  action: 'requested' | 'allowed' | 'denied';
  permission?: string;
  origin?: string;
  timestamp: number;
  responseTime?: number;
}
