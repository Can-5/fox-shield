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
