/** fox-shield Developer Mode — shared types. */

export interface RequestSample {
  method: string;
  url: string;
  headers: Record<string, string>;
}

export interface DarkEntry {
  hash: string;
  ip: string;
  reason: string;
  timestamp: number;
  sample: RequestSample;
  banned: boolean;
  destroyed: boolean;
}

export interface DevStats {
  rps: number;
  blockedToday: number;
  bannedIps: number;
  destroyed: number;
  threshold: number;
  aggressive: boolean;
}
