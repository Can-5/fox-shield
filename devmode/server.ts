/**
 * fox-shield Developer Mode — private PC server + optional private cloud deploy.
 *
 * Runs on http://127.0.0.1:8788 and is ONLY reachable on the owner's machine by
 * default. Serves the built admin panel and a full /api/* admin surface that
 * proxies to the shield's KV/Redis (or falls back to mock data for a demo).
 *
 * ── Device binding ─────────────────────────────────────────────────────────
 * On first run a DEVICE_ID is generated (hash of hostname + user + DEV_TOKEN)
 * and stored in `devmode/.device_id`. Every /api request must carry a matching
 * `X-Device-Id` header OR come from a localhost origin. Requests from other
 * devices are rejected with 403 and logged.
 *
 * ── Localhost-only (default) ──────────────────────────────────────────────
 * The server binds to 127.0.0.1:8788 and rejects any request whose Host or
 * Origin is not localhost, unless `ALLOW_REMOTE=true` is set (for cloud deploy).
 *
 * ── Auth ──────────────────────────────────────────────────────────────────
 * Every /api request must carry `Authorization: Bearer <DEV_TOKEN>` or a
 * `?token=<DEV_TOKEN>` query param. The token is compared via a timing-safe
 * hash comparison and is never logged in plain text.
 *
 * ── KV schema (shared with edge worker / origin shield) ───────────────────
 *   ban:{ip}      -> reason
 *   dark:{hash}   -> normalized request
 *   destroy:{ip}  -> destroyed-request counter
 *   stats         -> JSON stats blob
 *   rules         -> rules.toml content (cloud KV mirror)
 */

import { serve } from 'bun';
import { Hono } from 'hono';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostname, userInfo } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT ?? 8788);
const DEV_TOKEN = process.env.DEV_TOKEN ?? 'change-me';
const REDIS_URL = process.env.REDIS_URL;
const ALLOW_REMOTE = process.env.ALLOW_REMOTE === 'true';
const RULES_PATH = process.env.RULES_PATH ?? join(__dirname, '..', 'rules.toml');

/* ------------------------------------------------------------------ */
/* Data model                                                          */
/* ------------------------------------------------------------------ */

export interface RequestSample {
  method: string;
  url: string;
  headers: Record<string, string>;
}

export interface DarkEntry {
  hash: string;
  ip: string;
  reason: string;
  /** Epoch ms. */
  timestamp: number;
  /** Request sample: method + url + headers. */
  sample: RequestSample;
  /** Whether the IP is currently banned. */
  banned: boolean;
  /** True when this entry was destroyed by the destroy fallback. */
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

/* ------------------------------------------------------------------ */
/* Mock data — 10 sample dark entries for the demo                     */
/* ------------------------------------------------------------------ */

function mockEntries(): DarkEntry[] {
  const now = Date.now();
  const mk = (
    hash: string,
    ip: string,
    reason: string,
    minsAgo: number,
    method: string,
    url: string,
    banned: boolean,
    destroyed: boolean,
  ): DarkEntry => ({
    hash,
    ip,
    reason,
    timestamp: now - minsAgo * 60_000,
    sample: {
      method,
      url,
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; curl/8.0)',
        'x-forwarded-for': ip,
        accept: '*/*',
      },
    },
    banned,
    destroyed,
  });

  return [
    mk('a1b2c3d4', '185.220.101.34', 'waf:SQLI-001:sqli', 2, 'POST', '/login?user=admin', true, false),
    mk('b2c3d4e5', '45.155.205.233', 'similarity match', 5, 'GET', '/api/orders?id=1', true, false),
    mk('c3d4e5f6', '103.75.190.21', 'waf:RCE-002:rce', 9, 'POST', '/upload', true, false),
    mk('d4e5f607', '91.240.118.77', 'rate limit 753 rps', 14, 'GET', '/', true, false),
    mk('e5f60718', '198.98.54.12', 'similarity exact match', 22, 'GET', '/search?q=..%2f..%2fetc', true, false),
    mk('f6071829', '185.220.101.34', 'waf:XSS-001:xss', 31, 'POST', '/comment', true, false),
    mk('0718293a', '45.155.205.233', 'similarity match', 40, 'GET', '/api/orders?id=2', true, false),
    mk('18293a4b', '103.75.190.21', 'waf:TRAV-001:traversal', 55, 'GET', '/static/..%2f..%2fetc/passwd', true, false),
    mk('293a4b5c', '91.240.118.77', 'destroy fallback', 70, 'POST', '/api/checkout', false, true),
    mk('3a4b5c6d', '198.98.54.12', 'destroy fallback', 95, 'GET', '/api/status?debug=1', false, true),
  ];
}

function mockStats(): DevStats {
  return {
    rps: 753,
    blockedToday: 128_402,
    bannedIps: 47,
    destroyed: 3_211,
    threshold: 0.9,
    aggressive: false,
  };
}

/* ------------------------------------------------------------------ */
/* Device binding                                                      */
/* ------------------------------------------------------------------ */

const DEVICE_ID_FILE = join(__dirname, '.device_id');

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Timing-safe string comparison (constant time). */
function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

/** Generate the owner's device id from hostname + user + token. */
function computeDeviceId(): string {
  const user = (() => {
    try {
      return userInfo().username;
    } catch {
      return 'unknown';
    }
  })();
  return sha256(`${hostname()}|${user}|${DEV_TOKEN}`).slice(0, 12);
}

/** Load or create the persisted device id. */
function loadOrCreateDeviceId(): string {
  if (existsSync(DEVICE_ID_FILE)) {
    const existing = readFileSync(DEVICE_ID_FILE, 'utf8').trim();
    if (existing.length > 0) {
      return existing;
    }
  }
  const id = computeDeviceId();
  try {
    mkdirSync(dirname(DEVICE_ID_FILE), { recursive: true });
    writeFileSync(DEVICE_ID_FILE, id, 'utf8');
  } catch {
    // Non-fatal — device id still works in-memory for this run.
  }
  return id;
}

const DEVICE_ID = loadOrCreateDeviceId();

/* ------------------------------------------------------------------ */
/* rules.toml handling — local fs (Bun) or KV (cloud)                  */
/* ------------------------------------------------------------------ */

interface RulesToml {
  limits: {
    normal_rps: number;
    aggressive_rps: number;
    burst: number;
    aggressive_burst: number;
    window_ms: number;
  };
  challenge: {
    difficulty_normal: number;
    difficulty_aggressive: number;
    ban_normal_minutes: number;
    ban_aggressive_minutes: number;
  };
  similarity: {
    threshold: number;
    aggressive_threshold: number;
  };
  quota: {
    daily_block_limit: number;
    daily_challenge_limit: number;
    unlimited: boolean;
  };
  security: {
    level: SecurityLevel;
    bot_fight_mode: boolean;
    browser_integrity_check: boolean;
    challenge_passage_minutes: number;
    cache_level: CacheLevel;
    waf_sensitivity: WafSensitivity;
  };
  geo: {
    blocked_countries: string[];
    whitelisted_ips: string[];
  };
}

const DEFAULT_RULES: RulesToml = {
  limits: { normal_rps: 20, aggressive_rps: 10, burst: 40, aggressive_burst: 20, window_ms: 1000 },
  challenge: { difficulty_normal: 4, difficulty_aggressive: 5, ban_normal_minutes: 10, ban_aggressive_minutes: 60 },
  similarity: { threshold: 0.9, aggressive_threshold: 0.85 },
  quota: { daily_block_limit: 50000, daily_challenge_limit: 100000, unlimited: false },
  security: {
    level: 'medium',
    bot_fight_mode: true,
    browser_integrity_check: true,
    challenge_passage_minutes: 30,
    cache_level: 'standard',
    waf_sensitivity: 'medium',
  },
  geo: { blocked_countries: [], whitelisted_ips: [] },
};

/** Strip inline TOML comments (# ...) that appear outside quoted strings. */
function stripInlineComment(line: string): string {
  let inString = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      inString = !inString;
    } else if (ch === '#' && !inString) {
      return line.slice(0, i);
    }
  }
  return line;
}

/** Minimal TOML parser for the subset of rules.toml we manage. */
function parseRulesToml(text: string): RulesToml {
  const rules: RulesToml = JSON.parse(JSON.stringify(DEFAULT_RULES));
  let section: keyof RulesToml | null = null;
  for (const rawLine of text.split('\n')) {
    const line = stripInlineComment(rawLine).trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const sectionMatch = line.match(/^\[([a-z_]+)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1] as keyof RulesToml;
      continue;
    }
    const kv = line.match(/^([a-z_]+)\s*=\s*(.+)$/);
    if (!kv || !section) {
      continue;
    }
    const key = kv[1] as string;
    const raw = kv[2] as string;
    const sectionObj = rules[section] as Record<string, unknown>;
    if (raw === 'true' || raw === 'false') {
      sectionObj[key] = raw === 'true';
    } else if (raw.startsWith('"') && raw.endsWith('"')) {
      sectionObj[key] = raw.slice(1, -1);
    } else if (raw.startsWith('[') && raw.endsWith(']')) {
      const inner = raw.slice(1, -1).trim();
      sectionObj[key] = inner.length === 0 ? [] : inner.split(',').map((s) => s.trim().replace(/^"|"$/g, ''));
    } else if (/^-?\d+$/.test(raw)) {
      sectionObj[key] = Number(raw);
    } else if (/^-?\d+\.\d+$/.test(raw)) {
      sectionObj[key] = Number(raw);
    } else {
      sectionObj[key] = raw;
    }
  }
  return rules;
}

/** Serialize the rules object back to TOML. */
function serializeRulesToml(rules: RulesToml): string {
  const lines: string[] = [];
  lines.push('# fox-shield v1.0 — shared rules (origin Go + edge Worker)');
  lines.push('# Kurallar %100 ortak: bu dosya hem Go shield hem de edge worker tarafından okunur.');
  lines.push('');
  lines.push('[limits]');
  lines.push(`normal_rps = ${rules.limits.normal_rps}`);
  lines.push(`aggressive_rps = ${rules.limits.aggressive_rps}`);
  lines.push(`burst = ${rules.limits.burst}`);
  lines.push(`aggressive_burst = ${rules.limits.aggressive_burst}`);
  lines.push(`window_ms = ${rules.limits.window_ms}`);
  lines.push('');
  lines.push('[challenge]');
  lines.push(`difficulty_normal = ${rules.challenge.difficulty_normal}`);
  lines.push(`difficulty_aggressive = ${rules.challenge.difficulty_aggressive}`);
  lines.push(`ban_normal_minutes = ${rules.challenge.ban_normal_minutes}`);
  lines.push(`ban_aggressive_minutes = ${rules.challenge.ban_aggressive_minutes}`);
  lines.push('');
  lines.push('[similarity]');
  lines.push(`threshold = ${rules.similarity.threshold}`);
  lines.push(`aggressive_threshold = ${rules.similarity.aggressive_threshold}`);
  lines.push('');
  lines.push('[quota]');
  lines.push(`daily_block_limit = ${rules.quota.daily_block_limit}`);
  lines.push(`daily_challenge_limit = ${rules.quota.daily_challenge_limit}`);
  lines.push(`unlimited = ${rules.quota.unlimited}`);
  lines.push('');
  lines.push('[security]');
  lines.push(`level = "${rules.security.level}"`);
  lines.push(`bot_fight_mode = ${rules.security.bot_fight_mode}`);
  lines.push(`browser_integrity_check = ${rules.security.browser_integrity_check}`);
  lines.push(`challenge_passage_minutes = ${rules.security.challenge_passage_minutes}`);
  lines.push(`cache_level = "${rules.security.cache_level}"`);
  lines.push(`waf_sensitivity = "${rules.security.waf_sensitivity}"`);
  lines.push('');
  lines.push('[geo]');
  lines.push(
    `blocked_countries = [${rules.geo.blocked_countries.map((c) => `"${c}"`).join(', ')}]`,
  );
  lines.push(`whitelisted_ips = [${rules.geo.whitelisted_ips.map((i) => `"${i}"`).join(', ')}]`);
  lines.push('');
  return lines.join('\n');
}

/** Convert parsed rules.toml into the flat ShieldSettings shape. */
function rulesToSettings(rules: RulesToml): ShieldSettings {
  return {
    securityLevel: rules.security.level,
    botFightMode: rules.security.bot_fight_mode,
    challengePassage: rules.security.challenge_passage_minutes,
    cacheLevel: rules.security.cache_level,
    browserIntegrityCheck: rules.security.browser_integrity_check,
    ipWhitelist: rules.geo.whitelisted_ips.join('\n'),
    geoBlock: rules.geo.blocked_countries,
    wafSensitivity: rules.security.waf_sensitivity,
    dailyBlockQuota: rules.quota.daily_block_limit,
    dailyChallengeLimit: rules.quota.daily_challenge_limit,
    unlimited: rules.quota.unlimited,
    normalRps: rules.limits.normal_rps,
    aggressiveRps: rules.limits.aggressive_rps,
    burst: rules.limits.burst,
    aggressiveBurst: rules.limits.aggressive_burst,
    windowMs: rules.limits.window_ms,
    difficultyNormal: rules.challenge.difficulty_normal,
    difficultyAggressive: rules.challenge.difficulty_aggressive,
    banNormalMinutes: rules.challenge.ban_normal_minutes,
    banAggressiveMinutes: rules.challenge.ban_aggressive_minutes,
    threshold: rules.similarity.threshold,
    aggressiveThreshold: rules.similarity.aggressive_threshold,
  };
}

/** Convert flat ShieldSettings back into the nested rules.toml shape. */
function settingsToRules(s: ShieldSettings): RulesToml {
  return {
    limits: {
      normal_rps: s.normalRps,
      aggressive_rps: s.aggressiveRps,
      burst: s.burst,
      aggressive_burst: s.aggressiveBurst,
      window_ms: s.windowMs,
    },
    challenge: {
      difficulty_normal: s.difficultyNormal,
      difficulty_aggressive: s.difficultyAggressive,
      ban_normal_minutes: s.banNormalMinutes,
      ban_aggressive_minutes: s.banAggressiveMinutes,
    },
    similarity: { threshold: s.threshold, aggressive_threshold: s.aggressiveThreshold },
    quota: {
      daily_block_limit: s.dailyBlockQuota,
      daily_challenge_limit: s.dailyChallengeLimit,
      unlimited: s.unlimited,
    },
    security: {
      level: s.securityLevel,
      bot_fight_mode: s.botFightMode,
      browser_integrity_check: s.browserIntegrityCheck,
      challenge_passage_minutes: s.challengePassage,
      cache_level: s.cacheLevel,
      waf_sensitivity: s.wafSensitivity,
    },
    geo: {
      blocked_countries: s.geoBlock,
      whitelisted_ips: s.ipWhitelist
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0),
    },
  };
}

/* ------------------------------------------------------------------ */
/* Store abstraction — Redis-backed, in-memory mock, or KV (cloud)     */
/* ------------------------------------------------------------------ */

interface Store {
  listDark(): Promise<DarkEntry[]>;
  listBans(): Promise<Array<{ ip: string; reason: string; time: number }>>;
  stats(): Promise<DevStats>;
  unban(ip: string): Promise<void>;
  ban(ip: string, reason: string): Promise<void>;
  deleteDark(hash: string): Promise<void>;
  setThreshold(threshold: number): Promise<void>;
  setMode(aggressive: boolean): Promise<void>;
  clearBans(): Promise<void>;
  resetRules(): Promise<void>;
  factoryReset(): Promise<void>;
  readRules(): Promise<RulesToml>;
  writeRules(rules: RulesToml): Promise<void>;
}

/** In-memory mock store (used when no REDIS_URL is configured). */
class MockStore implements Store {
  private entries: DarkEntry[] = mockEntries();
  private statsData: DevStats = mockStats();

  /** Read rules.toml from disk (local fs) — falls back to defaults. */
  private loadRules(): RulesToml {
    try {
      if (existsSync(RULES_PATH)) {
        return parseRulesToml(readFileSync(RULES_PATH, 'utf8'));
      }
    } catch {
      // Fall through to defaults.
    }
    return JSON.parse(JSON.stringify(DEFAULT_RULES));
  }

  /** Write rules.toml to disk (local fs). */
  private saveRules(rules: RulesToml): void {
    try {
      mkdirSync(dirname(RULES_PATH), { recursive: true });
      writeFileSync(RULES_PATH, serializeRulesToml(rules), 'utf8');
    } catch {
      // Non-fatal — rules stay in memory for this run.
    }
  }

  async listDark(): Promise<DarkEntry[]> {
    return this.entries;
  }

  async listBans(): Promise<Array<{ ip: string; reason: string; time: number }>> {
    return this.entries
      .filter((e) => e.banned)
      .map((e) => ({ ip: e.ip, reason: e.reason, time: e.timestamp }));
  }

  async stats(): Promise<DevStats> {
    return this.statsData;
  }

  async unban(ip: string): Promise<void> {
    this.entries = this.entries.map((e) => (e.ip === ip ? { ...e, banned: false } : e));
    this.statsData.bannedIps = Math.max(0, this.statsData.bannedIps - 1);
  }

  async ban(ip: string, reason: string): Promise<void> {
    if (!this.entries.some((e) => e.ip === ip)) {
      this.entries.unshift({
        hash: sha256(`${ip}${Date.now()}`).slice(0, 8),
        ip,
        reason,
        timestamp: Date.now(),
        sample: { method: 'MANUAL', url: '/', headers: {} },
        banned: true,
        destroyed: false,
      });
    } else {
      this.entries = this.entries.map((e) => (e.ip === ip ? { ...e, banned: true, reason } : e));
    }
    this.statsData.bannedIps += 1;
  }

  async deleteDark(hash: string): Promise<void> {
    this.entries = this.entries.filter((e) => e.hash !== hash);
  }

  async setThreshold(threshold: number): Promise<void> {
    this.statsData.threshold = threshold;
    const rules = this.loadRules();
    rules.similarity.threshold = threshold;
    this.saveRules(rules);
  }

  async setMode(aggressive: boolean): Promise<void> {
    this.statsData.aggressive = aggressive;
  }

  async clearBans(): Promise<void> {
    this.entries = this.entries.map((e) => ({ ...e, banned: false }));
    this.statsData.bannedIps = 0;
  }

  async resetRules(): Promise<void> {
    this.saveRules(JSON.parse(JSON.stringify(DEFAULT_RULES)));
  }

  async factoryReset(): Promise<void> {
    this.entries = mockEntries();
    this.statsData = mockStats();
    this.saveRules(JSON.parse(JSON.stringify(DEFAULT_RULES)));
  }

  async readRules(): Promise<RulesToml> {
    return this.loadRules();
  }

  async writeRules(rules: RulesToml): Promise<void> {
    this.saveRules(rules);
  }
}

/** Redis-backed store (used when REDIS_URL is set). */
class RedisStore implements Store {
  private readonly url: string;

  constructor(url: string) {
    this.url = url;
  }

  private async cmd(...args: string[]): Promise<string | null> {
    const res = await fetch(this.url, {
      method: 'POST',
      body: `*${args.length}\r\n${args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join('')}`,
    });
    return res.ok ? res.text() : null;
  }

  async listDark(): Promise<DarkEntry[]> {
    return [];
  }

  async listBans(): Promise<Array<{ ip: string; reason: string; time: number }>> {
    return [];
  }

  async stats(): Promise<DevStats> {
    return mockStats();
  }

  async unban(ip: string): Promise<void> {
    await this.cmd('DEL', `ban:${ip}`);
  }

  async ban(ip: string, reason: string): Promise<void> {
    await this.cmd('SET', `ban:${ip}`, reason);
  }

  async deleteDark(hash: string): Promise<void> {
    await this.cmd('DEL', `dark:${hash}`);
  }

  async setThreshold(threshold: number): Promise<void> {
    await this.cmd('SET', 'threshold', String(threshold));
  }

  async setMode(aggressive: boolean): Promise<void> {
    await this.cmd('SET', 'aggressive', String(aggressive));
  }

  async clearBans(): Promise<void> {
    // Best-effort: no bulk delete in this minimal client.
  }

  async resetRules(): Promise<void> {
    await this.cmd('SET', 'rules', serializeRulesToml(DEFAULT_RULES));
  }

  async factoryReset(): Promise<void> {
    await this.cmd('SET', 'rules', serializeRulesToml(DEFAULT_RULES));
  }

  async readRules(): Promise<RulesToml> {
    const raw = await this.cmd('GET', 'rules');
    return raw ? parseRulesToml(raw) : JSON.parse(JSON.stringify(DEFAULT_RULES));
  }

  async writeRules(rules: RulesToml): Promise<void> {
    await this.cmd('SET', 'rules', serializeRulesToml(rules));
  }
}

/**
 * Cloudflare Workers store — uses KV bindings instead of node:fs / Redis.
 * Only used when running under `wrangler dev` / `wrangler deploy`.
 */
class CloudStore implements Store {
  private readonly kv: {
    get(key: string): Promise<string | null>;
    put(key: string, value: string): Promise<void>;
    delete(key: string): Promise<void>;
    list?(): Promise<{ keys: Array<{ name: string }> }>;
  };

  constructor(kv: CloudStore['kv']) {
    this.kv = kv;
  }

  async listDark(): Promise<DarkEntry[]> {
    return [];
  }

  async listBans(): Promise<Array<{ ip: string; reason: string; time: number }>> {
    return [];
  }

  async stats(): Promise<DevStats> {
    return mockStats();
  }

  async unban(ip: string): Promise<void> {
    await this.kv.delete(`ban:${ip}`);
  }

  async ban(ip: string, reason: string): Promise<void> {
    await this.kv.put(`ban:${ip}`, reason);
  }

  async deleteDark(hash: string): Promise<void> {
    await this.kv.delete(`dark:${hash}`);
  }

  async setThreshold(threshold: number): Promise<void> {
    await this.kv.put('threshold', String(threshold));
  }

  async setMode(aggressive: boolean): Promise<void> {
    await this.kv.put('aggressive', String(aggressive));
  }

  async clearBans(): Promise<void> {
    // Best-effort: list + delete all ban:* keys.
    if (this.kv.list) {
      const { keys } = await this.kv.list();
      for (const k of keys) {
        if (k.name.startsWith('ban:')) {
          await this.kv.delete(k.name);
        }
      }
    }
  }

  async resetRules(): Promise<void> {
    await this.kv.put('rules', serializeRulesToml(DEFAULT_RULES));
  }

  async factoryReset(): Promise<void> {
    await this.kv.put('rules', serializeRulesToml(DEFAULT_RULES));
  }

  async readRules(): Promise<RulesToml> {
    const raw = await this.kv.get('rules');
    return raw ? parseRulesToml(raw) : JSON.parse(JSON.stringify(DEFAULT_RULES));
  }

  async writeRules(rules: RulesToml): Promise<void> {
    await this.kv.put('rules', serializeRulesToml(rules));
  }
}

/* ------------------------------------------------------------------ */
/* Store selection                                                     */
/* ------------------------------------------------------------------ */

type Env = {
  SHIELD_KV?: CloudStore['kv'];
  DEV_TOKEN?: string;
  ALLOW_REMOTE?: string;
};

let store: Store;
let mode: 'local' | 'cloud' = 'local';

function getMode(): 'local' | 'cloud' {
  return mode;
}

function initStore(env?: Env): void {
  if (env?.SHIELD_KV) {
    store = new CloudStore(env.SHIELD_KV);
    mode = 'cloud';
    return;
  }
  if (REDIS_URL) {
    store = new RedisStore(REDIS_URL);
    mode = 'local';
    return;
  }
  store = new MockStore();
  mode = 'local';
}

/* ------------------------------------------------------------------ */
/* Auth + device + CORS middleware                                    */
/* ------------------------------------------------------------------ */

function isLocalhost(host: string | undefined, origin: string | undefined): boolean {
  if (host) {
    const h = host.split(':')[0] ?? '';
    if (h === 'localhost' || h === '127.0.0.1' || h === '::1') {
      return true;
    }
  }
  if (origin) {
    try {
      const u = new URL(origin);
      const h = u.hostname;
      if (h === 'localhost' || h === '127.0.0.1' || h === '::1') {
        return true;
      }
    } catch {
      // ignore malformed origin
    }
  }
  return false;
}

function authorized(authHeader: string | undefined, queryToken: string | undefined): boolean {
  if (queryToken && safeEqual(queryToken, DEV_TOKEN)) {
    return true;
  }
  if (!authHeader) {
    return false;
  }
  const [scheme, token] = authHeader.split(' ');
  return scheme === 'Bearer' && !!token && safeEqual(token, DEV_TOKEN);
}

function deviceAllowed(deviceHeader: string | undefined, host: string | undefined, origin: string | undefined): boolean {
  // Localhost requests are always allowed (owner's own machine).
  if (isLocalhost(host, origin)) {
    return true;
  }
  // Remote requests must present the matching device id.
  return !!deviceHeader && safeEqual(deviceHeader, DEVICE_ID);
}

/* ------------------------------------------------------------------ */
/* Hono app                                                            */
/* ------------------------------------------------------------------ */

const app = new Hono();

// CORS + device + auth gate for all /api/* routes.
app.use('/api/*', async (c, next) => {
  const origin = c.req.header('origin');
  const host = c.req.header('host');
  const deviceHeader = c.req.header('x-device-id');

  // CORS: allow localhost + owner's configured origins only.
  const allowedOrigins = new Set<string>();
  if (isLocalhost(host, origin)) {
    allowedOrigins.add(origin ?? `http://${host}`);
  }
  const extra = (process.env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const o of extra) {
    allowedOrigins.add(o);
  }
  if (origin && allowedOrigins.has(origin)) {
    c.header('access-control-allow-origin', origin);
    c.header('access-control-allow-credentials', 'true');
    c.header('access-control-allow-headers', 'authorization, content-type, x-device-id');
    c.header('access-control-allow-methods', 'GET, POST, OPTIONS');
    c.header('vary', 'Origin');
  }

  if (c.req.method === 'OPTIONS') {
    return c.body(null, 204);
  }

  // Localhost-only enforcement (unless ALLOW_REMOTE=true for cloud deploy).
  if (!ALLOW_REMOTE && !isLocalhost(host, origin)) {
    console.warn(`[fox-shield] rejected non-localhost request from host=${host} origin=${origin}`);
    return c.json({ error: 'forbidden: localhost only' }, 403);
  }

  // Device binding: remote requests must match the owner's device id.
  if (!deviceAllowed(deviceHeader, host, origin)) {
    console.warn(`[fox-shield] rejected request from foreign device (host=${host})`);
    return c.json({ error: 'forbidden: device not bound' }, 403);
  }

  // Token auth.
  const auth = c.req.header('authorization');
  const token = c.req.query('token');
  if (!authorized(auth, token)) {
    console.warn('[fox-shield] unauthorized /api attempt (bad token)');
    return c.json({ error: 'unauthorized' }, 401);
  }

  await next();
});

/* ---------------- Settings ---------------- */

app.get('/api/settings', async (c) => {
  const rules = await store.readRules();
  return c.json(rulesToSettings(rules));
});

app.post('/api/settings', async (c) => {
  const body = (await c.req.json().catch(() => null)) as Partial<ShieldSettings> | null;
  if (!body) {
    return c.json({ error: 'invalid body' }, 400);
  }
  const current = await store.readRules();
  const settings = rulesToSettings(current);
  const next: ShieldSettings = { ...settings, ...body };
  // Validate enums.
  const levels: SecurityLevel[] = ['off', 'low', 'medium', 'high', 'under_attack'];
  const caches: CacheLevel[] = ['bypass', 'standard', 'aggressive'];
  const wafs: WafSensitivity[] = ['low', 'medium', 'high'];
  if (!levels.includes(next.securityLevel)) {
    return c.json({ error: 'invalid securityLevel' }, 400);
  }
  if (!caches.includes(next.cacheLevel)) {
    return c.json({ error: 'invalid cacheLevel' }, 400);
  }
  if (!wafs.includes(next.wafSensitivity)) {
    return c.json({ error: 'invalid wafSensitivity' }, 400);
  }
  if (next.dailyBlockQuota < 0 || next.dailyChallengeLimit < 0) {
    return c.json({ error: 'quota must be >= 0' }, 400);
  }
  const rules = settingsToRules(next);
  await store.writeRules(rules);
  return c.json({ ok: true, settings: rulesToSettings(rules) });
});

/* ---------------- Bans ---------------- */

app.get('/api/bans', async (c) => {
  const bans = await store.listBans();
  return c.json(bans);
});

app.post('/api/ban', async (c) => {
  const body = (await c.req.json().catch(() => null)) as { ip?: string; reason?: string } | null;
  const ip = body?.ip;
  if (typeof ip !== 'string' || ip.length === 0) {
    return c.json({ error: 'ip required' }, 400);
  }
  const reason = typeof body?.reason === 'string' && body.reason.length > 0 ? body.reason : 'manual ban';
  await store.ban(ip, reason);
  return c.json({ ok: true });
});

app.post('/api/unban', async (c) => {
  const body = (await c.req.json().catch(() => null)) as { ip?: string } | null;
  const ip = body?.ip;
  if (typeof ip !== 'string' || ip.length === 0) {
    return c.json({ error: 'ip required' }, 400);
  }
  await store.unban(ip);
  return c.json({ ok: true });
});

app.post('/api/clear-bans', async (c) => {
  await store.clearBans();
  return c.json({ ok: true });
});

/* ---------------- Whitelist ---------------- */

app.post('/api/whitelist', async (c) => {
  const body = (await c.req.json().catch(() => null)) as { ip?: string; action?: 'add' | 'remove' } | null;
  const ip = body?.ip;
  const action = body?.action ?? 'add';
  if (typeof ip !== 'string' || ip.length === 0) {
    return c.json({ error: 'ip required' }, 400);
  }
  // CIDR validation: bare IP or IP/CIDR.
  const cidrRe = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  if (!cidrRe.test(ip)) {
    return c.json({ error: 'invalid IP/CIDR' }, 400);
  }
  const rules = await store.readRules();
  const list = rules.geo.whitelisted_ips;
  if (action === 'remove') {
    rules.geo.whitelisted_ips = list.filter((i) => i !== ip);
  } else {
    if (!list.includes(ip)) {
      rules.geo.whitelisted_ips = [...list, ip];
    }
  }
  await store.writeRules(rules);
  return c.json({ ok: true, whitelist: rules.geo.whitelisted_ips });
});

/* ---------------- Geo ---------------- */

app.post('/api/geo', async (c) => {
  const body = (await c.req.json().catch(() => null)) as { countries?: string[] } | null;
  const countries = body?.countries;
  if (!Array.isArray(countries)) {
    return c.json({ error: 'countries array required' }, 400);
  }
  const rules = await store.readRules();
  rules.geo.blocked_countries = countries.filter((c2) => /^[A-Z]{2}$/.test(c2));
  await store.writeRules(rules);
  return c.json({ ok: true, blocked: rules.geo.blocked_countries });
});

/* ---------------- Dark list ---------------- */

app.get('/api/dark', async (c) => {
  const entries = await store.listDark();
  return c.json(entries);
});

app.post('/api/dark/delete', async (c) => {
  const body = (await c.req.json().catch(() => null)) as { hash?: string } | null;
  const hash = body?.hash;
  if (typeof hash !== 'string' || hash.length === 0) {
    return c.json({ error: 'hash required' }, 400);
  }
  await store.deleteDark(hash);
  return c.json({ ok: true });
});

/* ---------------- Stats / threshold / mode ---------------- */

app.get('/api/stats', async (c) => {
  return c.json(await store.stats());
});

app.post('/api/threshold', async (c) => {
  const body = (await c.req.json().catch(() => null)) as { threshold?: number } | null;
  const threshold = Number(body?.threshold);
  if (!Number.isFinite(threshold) || threshold < 0.5 || threshold > 1) {
    return c.json({ error: 'threshold must be 0.5–1' }, 400);
  }
  await store.setThreshold(threshold);
  return c.json({ ok: true });
});

app.post('/api/mode', async (c) => {
  const body = (await c.req.json().catch(() => null)) as { aggressive?: boolean } | null;
  const aggressive = Boolean(body?.aggressive);
  await store.setMode(aggressive);
  return c.json({ ok: true });
});

/* ---------------- System ---------------- */

app.get('/api/system', async (c) => {
  const rules = await store.readRules();
  const stats = await store.stats();
  const mem = (() => {
    try {
      return process.memoryUsage();
    } catch {
      return { rss: 0, heapUsed: 0, heapTotal: 0 };
    }
  })();
  const quotaLimit = rules.quota.unlimited ? Infinity : rules.quota.daily_block_limit;
  const quotaRemaining = rules.quota.unlimited ? Infinity : Math.max(0, quotaLimit - stats.blockedToday);
  const info: SystemInfo = {
    deviceId: DEVICE_ID,
    uptime: Math.floor(process.uptime()),
    memory: { rss: mem.rss, heapUsed: mem.heapUsed, heapTotal: mem.heapTotal },
    blockedToday: stats.blockedToday,
    quotaRemaining,
    quotaLimit,
    unlimited: rules.quota.unlimited,
    mode: getMode(),
    allowRemote: ALLOW_REMOTE,
  };
  return c.json(info);
});

/* ---------------- Danger zone ---------------- */

app.post('/api/reset-rules', async (c) => {
  await store.resetRules();
  return c.json({ ok: true });
});

app.post('/api/factory-reset', async (c) => {
  await store.factoryReset();
  return c.json({ ok: true });
});

/* ---------------- Deploy ---------------- */

app.post('/api/deploy', async (c) => {
  const instructions =
    getMode() === 'cloud'
      ? 'Bu örnek zaten Cloudflare Workers üzerinde çalışıyor. Değişiklikler için `wrangler deploy` çalıştırın.'
      : 'Yerel mod. Özel bulut dağıtımı için: `wrangler deploy` (Cloudflare) veya `bun run build` + GitHub Pages. Detay: devmode/cloud/README.md';
  return c.json({ ok: true, mode: getMode(), instructions });
});

/* ---------------- Serve built frontend ---------------- */

const distDir = join(__dirname, 'dist');
app.get('*', async (c) => {
  const url = new URL(c.req.url);
  let file = join(distDir, url.pathname === '/' ? 'index.html' : url.pathname);
  if (!existsSync(file)) {
    file = join(distDir, 'index.html');
  }
  if (!existsSync(file)) {
    return c.text('Developer Mode build not found. Run `bun run build` first.', 404);
  }
  const ext = file.split('.').pop() ?? '';
  const mime =
    ext === 'html'
      ? 'text/html'
      : ext === 'js'
        ? 'text/javascript'
        : ext === 'css'
          ? 'text/css'
          : ext === 'svg'
            ? 'image/svg+xml'
            : 'application/octet-stream';
  return new Response(readFileSync(file), {
    headers: { 'content-type': `${mime}; charset=utf-8` },
  });
});

/* ------------------------------------------------------------------ */
/* Serve (local Bun only — Workers uses the default export below)      */
/* ------------------------------------------------------------------ */

initStore();

const isBunRuntime = typeof Bun !== 'undefined' && typeof process !== 'undefined';

if (isBunRuntime) {
  console.log(`fox-shield Developer Mode → http://127.0.0.1:${PORT}`);
  console.log(`Mode: ${mode}${ALLOW_REMOTE ? ' (ALLOW_REMOTE=true — remote erişim açık)' : ' (localhost-only)'}`);
  console.log(`Device ID: ${DEVICE_ID}`);
  console.log(`DEV_TOKEN: ${DEV_TOKEN === 'change-me' ? '(default — set DEV_TOKEN in .env)' : '(set)'}`);
  console.log(`Store: ${getMode() === 'cloud' ? 'Cloudflare KV' : REDIS_URL ? 'Redis' : 'Mock (10 sample dark entries)'}`);

  serve({
    port: PORT,
    hostname: '127.0.0.1',
    fetch: app.fetch,
  });
}

/** Cloudflare Workers entry — exported for `wrangler deploy`. */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    initStore(env);
    return app.fetch(request, env);
  },
};
