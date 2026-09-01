/**
 * fox-shield dashboard — shared types.
 *
 * These mirror the edge worker / origin shield data shapes. The dashboard only
 * ever shows *summary* data (never the private dark list — that lives in
 * Developer Mode on the owner's PC).
 */

/** A banned IP entry (summary view — no request samples). */
export interface BanEntry {
  ip: string;
  reason: string;
  /** Epoch ms when the ban was recorded. */
  time: number;
}

/** Live shield statistics. */
export interface ShieldStats {
  /** Requests per second currently observed. */
  rps: number;
  /** Requests blocked today. */
  blockedToday: number;
  /** Number of currently banned IPs. */
  bannedIps: number;
  /** Requests destroyed by the destroy fallback (never reached origin). */
  destroyed: number;
  /** Top attacking countries by blocked count. */
  topCountries: Array<{ country: string; count: number }>;
  /** Top attacking IPs by blocked count. */
  topIps: Array<{ ip: string; count: number }>;
}

/** Aggressive mode state. */
export interface ModeState {
  aggressive: boolean;
}

/** Threshold configuration (similarity 0.85–0.95). */
export interface ThresholdState {
  threshold: number;
}

/** Security level presets, mirroring Cloudflare's Security Level control. */
export type SecurityLevel = 'off' | 'low' | 'medium' | 'high' | 'under_attack';

/** Cache level presets. */
export type CacheLevel = 'bypass' | 'standard' | 'aggressive';

/** WAF sensitivity presets. */
export type WafSensitivity = 'low' | 'medium' | 'high';

/**
 * Full shield configuration. Persisted to localStorage and exposed as JSON so
 * the edge worker / origin shield can read it.
 */
export interface ShieldSettings {
  /** Security level preset. */
  securityLevel: SecurityLevel;
  /** Bot Fight Mode toggle. */
  botFightMode: boolean;
  /** Challenge passage window in minutes (10–60). */
  challengePassage: number;
  /** Cache level. */
  cacheLevel: CacheLevel;
  /** Browser Integrity Check toggle. */
  browserIntegrityCheck: boolean;
  /** Whitelisted IPs, one per line. */
  ipWhitelist: string;
  /** Geo-blocked country codes (ISO 3166-1 alpha-2). */
  geoBlock: string[];
  /** WAF sensitivity. */
  wafSensitivity: WafSensitivity;
  /** Daily block quota before the shield hard-stops. */
  dailyBlockQuota: number;
}
