/**
 * fox-shield dashboard — API client.
 *
 * The dashboard is a static GitHub Pages site, so it cannot reach the shield's
 * KV/Redis directly. It polls a small `/api/*` surface when one is available
 * (e.g. a local devmode server or a future public stats endpoint) and falls
 * back to realistic mock data when the API is unreachable.
 */

import type { BanEntry, ModeState, ShieldSettings, ShieldStats, ThresholdState } from './types';

const API_BASE = import.meta.env.VITE_API_BASE ?? '';

/** Mock stats so the dashboard is fully functional without a backend. */
export const MOCK_STATS: ShieldStats = {
  rps: 753,
  blockedToday: 128_402,
  bannedIps: 47,
  destroyed: 3_211,
  topCountries: [
    { country: 'US', count: 41_220 },
    { country: 'DE', count: 28_940 },
    { country: 'NL', count: 19_310 },
    { country: 'RU', count: 15_780 },
    { country: 'CN', count: 12_450 },
    { country: 'BR', count: 10_702 },
  ],
  topIps: [
    { ip: '185.220.101.34', count: 9_812 },
    { ip: '45.155.205.233', count: 7_440 },
    { ip: '103.75.190.21', count: 6_120 },
    { ip: '91.240.118.77', count: 5_003 },
    { ip: '198.98.54.12', count: 4_221 },
  ],
};

export const MOCK_BANS: BanEntry[] = [
  { ip: '185.220.101.34', reason: 'waf:SQLI-001:sqli', time: Date.now() - 60_000 },
  { ip: '45.155.205.233', reason: 'similarity match', time: Date.now() - 3 * 60_000 },
  { ip: '103.75.190.21', reason: 'waf:RCE-002:rce', time: Date.now() - 9 * 60_000 },
  { ip: '91.240.118.77', reason: 'rate limit 753 rps', time: Date.now() - 14 * 60_000 },
  { ip: '198.98.54.12', reason: 'similarity exact match', time: Date.now() - 22 * 60_000 },
];

async function fetchJson<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { accept: 'application/json' },
    });
    if (!res.ok) {
      return null;
    }
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/** Polls live stats; returns mock data when the API is unavailable. */
export async function fetchStats(): Promise<{ stats: ShieldStats; live: boolean }> {
  const live = await fetchJson<ShieldStats>('/api/stats');
  return live ? { stats: live, live: true } : { stats: MOCK_STATS, live: false };
}

/** Fetches the current ban list; falls back to mock entries. */
export async function fetchBans(): Promise<BanEntry[]> {
  const live = await fetchJson<BanEntry[]>('/api/bans');
  return live ?? MOCK_BANS;
}

/** Reads aggressive mode; falls back to localStorage when no API. */
export async function fetchMode(): Promise<ModeState> {
  const live = await fetchJson<ModeState>('/api/mode');
  if (live) {
    return live;
  }
  return { aggressive: localStorage.getItem('fox-shield:aggressive') === 'true' };
}

/** Persists aggressive mode (API when available, else localStorage). */
export async function setMode(aggressive: boolean): Promise<void> {
  localStorage.setItem('fox-shield:aggressive', String(aggressive));
  try {
    await fetch(`${API_BASE}/api/mode`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ aggressive }),
    });
  } catch {
    // Static site without a backend — localStorage is the source of truth.
  }
}

/** Reads the similarity threshold; falls back to localStorage. */
export async function fetchThreshold(): Promise<ThresholdState> {
  const live = await fetchJson<ThresholdState>('/api/threshold');
  if (live) {
    return live;
  }
  const stored = Number(localStorage.getItem('fox-shield:threshold'));
  return { threshold: Number.isFinite(stored) && stored > 0 ? stored : 0.9 };
}

/** Persists the similarity threshold. */
export async function setThreshold(threshold: number): Promise<void> {
  localStorage.setItem('fox-shield:threshold', String(threshold));
  try {
    await fetch(`${API_BASE}/api/threshold`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ threshold }),
    });
  } catch {
    // localStorage fallback.
  }
}

/** Unbans an IP (best-effort; no-op on a static site). */
export async function unbanIp(ip: string): Promise<void> {
  try {
    await fetch(`${API_BASE}/api/unban`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ip }),
    });
  } catch {
    // Static site — nothing to call.
  }
}

const SETTINGS_KEY = 'fox-shield:settings';

/** Default shield configuration. */
export const DEFAULT_SETTINGS: ShieldSettings = {
  securityLevel: 'medium',
  botFightMode: true,
  challengePassage: 30,
  cacheLevel: 'standard',
  browserIntegrityCheck: true,
  ipWhitelist: '',
  geoBlock: [],
  wafSensitivity: 'medium',
  dailyBlockQuota: 50_000,
};

/** Loads shield settings from localStorage (falls back to defaults). */
export function loadSettings(): ShieldSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) {
      return DEFAULT_SETTINGS;
    }
    const parsed = JSON.parse(raw) as Partial<ShieldSettings>;
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

/** Persists shield settings to localStorage and exposes them as JSON. */
export function saveSettings(settings: ShieldSettings): void {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}

/** Returns the settings as a JSON string for the worker to read. */
export function settingsJson(settings: ShieldSettings): string {
  return JSON.stringify(settings, null, 2);
}
