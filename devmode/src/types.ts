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

export type SecurityLevel = 'off' | 'low' | 'medium' | 'high' | 'under_attack';
export type CacheLevel = 'bypass' | 'standard' | 'aggressive';
export type WafSensitivity = 'low' | 'medium' | 'high';

/** Full shield configuration — mirrors rules.toml + dashboard settings. */
export interface ShieldSettings {
  securityLevel: SecurityLevel;
  botFightMode: boolean;
  challengePassage: number;
  cacheLevel: CacheLevel;
  browserIntegrityCheck: boolean;
  ipWhitelist: string;
  geoBlock: string[];
  wafSensitivity: WafSensitivity;
  dailyBlockQuota: number;
  dailyChallengeLimit: number;
  unlimited: boolean;
  normalRps: number;
  aggressiveRps: number;
  burst: number;
  aggressiveBurst: number;
  windowMs: number;
  difficultyNormal: number;
  difficultyAggressive: number;
  banNormalMinutes: number;
  banAggressiveMinutes: number;
  threshold: number;
  aggressiveThreshold: number;
}

export interface SystemInfo {
  deviceId: string;
  uptime: number;
  memory: { rss: number; heapUsed: number; heapTotal: number };
  blockedToday: number;
  quotaRemaining: number;
  quotaLimit: number;
  unlimited: boolean;
  mode: 'local' | 'cloud';
  allowRemote: boolean;
}
