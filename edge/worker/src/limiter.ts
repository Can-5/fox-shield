/**
 * fox-shield edge worker — sliding-window rate limiter.
 *
 * Each IP (from CF-Connecting-IP) gets a sliding window of `windowMs`. The
 * window state is a JSON array of request timestamps stored in KV under
 * `ratelimit:{ip}`. Requests within the window are counted; when the count
 * reaches the sustained `rps` budget the request is rejected with 429 and a
 * Retry-After header. Exceeding the hard `burst` cap bans the IP immediately;
 * repeated sustained-rate violations also escalate to a ban.
 *
 * Normal mode: 20 rps / burst 40. Aggressive mode: 10 rps / burst 20.
 * Ban TTL: 10 minutes normal, 60 minutes aggressive.
 *
 * ── Consistency / TOCTOU ───────────────────────────────────────────────────
 * This edge limiter is BEST-EFFORT only. The window state is read then written
 * as separate KV operations (get + set), so concurrent requests from the same
 * IP can race (TOCTOU) and Cloudflare KV is eventually consistent — a burst
 * can slip through under load. The authoritative rate limit is enforced by the
 * Go origin limiter (cmd/shield), which runs in-memory and is race-free. Do
 * not rely on this edge limiter as the sole defense; treat it as a coarse
 * first line that reduces load on the origin.
 */

import type { Store } from './store';
import { rateLimitKey, banKey } from './store';

export interface LimiterConfig {
  normalRps: number;
  aggressiveRps: number;
  burst: number;
  aggressiveBurst: number;
  windowMs: number;
  banNormalSeconds: number;
  banAggressiveSeconds: number;
  violationsBeforeBan: number;
}

export const DEFAULT_LIMITER_CONFIG: LimiterConfig = {
  normalRps: 20,
  aggressiveRps: 10,
  burst: 40,
  aggressiveBurst: 20,
  windowMs: 1000,
  banNormalSeconds: 10 * 60,
  banAggressiveSeconds: 60 * 60,
  violationsBeforeBan: 3,
};

export const DAILY_BLOCK_LIMIT = 50000;
export const DAILY_CHALLENGE_LIMIT = 100000;

export interface AllowResult {
  ok: boolean;
  retryAfter: number;
  suspicious: boolean;
}

/** Parses a stored timestamp array, tolerating corrupt/absent data. */
function parseWindow(raw: string | null): number[] {
  if (!raw) {
    return [];
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
  } catch {
    return [];
  }
}

export class RateLimiter {
  private readonly store: Store;
  private readonly cfg: LimiterConfig;

  constructor(store: Store, cfg: LimiterConfig = DEFAULT_LIMITER_CONFIG) {
    this.store = store;
    this.cfg = cfg;
  }

  private params(aggressive: boolean): { rps: number; burst: number; banSeconds: number } {
    if (aggressive) {
      return {
        rps: this.cfg.aggressiveRps,
        burst: this.cfg.aggressiveBurst,
        banSeconds: this.cfg.banAggressiveSeconds,
      };
    }
    return {
      rps: this.cfg.normalRps,
      burst: this.cfg.burst,
      banSeconds: this.cfg.banNormalSeconds,
    };
  }

  /**
   * Evaluates a request from `ip`. Returns ok=false with a Retry-After when the
   * request is over budget, and bans the IP after repeated violations or an
   * immediate burst-cap breach.
   */
  async allow(ip: string, aggressive: boolean): Promise<AllowResult> {
    const { rps, burst, banSeconds } = this.params(aggressive);
    const key = rateLimitKey(ip);
    const now = Date.now();
    const windowStart = now - this.cfg.windowMs;

    const raw = await this.store.get(key);
    const timestamps = parseWindow(raw).filter((t) => t > windowStart);

    // Hard burst cap: breach bans immediately.
    if (timestamps.length >= burst) {
      await this.store.set(banKey(ip), 'rate-limit burst exceeded', banSeconds);
      return { ok: false, retryAfter: 1, suspicious: true };
    }

    // Sustained-rate budget.
    if (timestamps.length >= rps) {
      // Count violations via a per-IP counter stored alongside the window.
      const violKey = `${key}:viol`;
      const violRaw = await this.store.get(violKey);
      const violations = violRaw ? Number.parseInt(violRaw, 10) || 0 : 0;
      const next = violations + 1;
      await this.store.set(violKey, String(next), this.cfg.windowMs / 1000);

      if (next >= this.cfg.violationsBeforeBan) {
        await this.store.set(banKey(ip), 'rate-limit exceeded', banSeconds);
        await this.store.delete(violKey);
      }

      const retryAfter = Math.max(1, Math.ceil(this.cfg.windowMs / 1000));
      return { ok: false, retryAfter, suspicious: true };
    }

    // Within budget: record the request and persist the window.
    timestamps.push(now);
    await this.store.set(key, JSON.stringify(timestamps), Math.ceil(this.cfg.windowMs / 1000));

    // Suspicious when the window is >=80% consumed.
    const suspicious = timestamps.length >= rps * 0.8;
    return { ok: true, retryAfter: 0, suspicious };
  }
}
