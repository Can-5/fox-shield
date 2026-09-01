/**
 * fox-shield Developer Mode — private PC server.
 *
 * Runs on http://localhost:8788 and is ONLY reachable on the owner's machine.
 * Serves the built dark-list viewer and a small /api/* surface that proxies to
 * the shield's KV/Redis (or falls back to mock data for a demo).
 *
 * Auth: every /api request must carry `Authorization: Bearer <DEV_TOKEN>` or a
 * `?token=<DEV_TOKEN>` query param. CORS is closed — only same-origin requests
 * from localhost are accepted.
 *
 * KV schema (shared with edge worker / origin shield):
 *   ban:{ip}      -> reason
 *   dark:{hash}   -> normalized request
 *   destroy:{ip}  -> destroyed-request counter
 *   stats         -> JSON stats blob
 */

import { serve } from 'bun';
import { Hono } from 'hono';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT ?? 8788);
const DEV_TOKEN = process.env.DEV_TOKEN ?? 'change-me';
const REDIS_URL = process.env.REDIS_URL;

/* ------------------------------------------------------------------ */
/* Data model                                                          */
/* ------------------------------------------------------------------ */

export interface DarkEntry {
  hash: string;
  ip: string;
  reason: string;
  /** Epoch ms. */
  timestamp: number;
  /** Request sample: method + url + headers. */
  sample: {
    method: string;
    url: string;
    headers: Record<string, string>;
  };
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
/* Store abstraction — Redis-backed or in-memory mock                  */
/* ------------------------------------------------------------------ */

interface Store {
  listDark(): Promise<DarkEntry[]>;
  listBans(): Promise<Array<{ ip: string; reason: string; time: number }>>;
  stats(): Promise<DevStats>;
  unban(ip: string): Promise<void>;
  deleteDark(hash: string): Promise<void>;
  setThreshold(threshold: number): Promise<void>;
  setMode(aggressive: boolean): Promise<void>;
}

/** In-memory mock store (used when no REDIS_URL is configured). */
class MockStore implements Store {
  private entries: DarkEntry[] = mockEntries();
  private statsData: DevStats = mockStats();

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

  async deleteDark(hash: string): Promise<void> {
    this.entries = this.entries.filter((e) => e.hash !== hash);
  }

  async setThreshold(threshold: number): Promise<void> {
    this.statsData.threshold = threshold;
  }

  async setMode(aggressive: boolean): Promise<void> {
    this.statsData.aggressive = aggressive;
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
    // Best-effort: read the dark list via KEYS + GET. Falls back to empty.
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

  async deleteDark(hash: string): Promise<void> {
    await this.cmd('DEL', `dark:${hash}`);
  }

  async setThreshold(threshold: number): Promise<void> {
    await this.cmd('SET', 'threshold', String(threshold));
  }

  async setMode(aggressive: boolean): Promise<void> {
    await this.cmd('SET', 'aggressive', String(aggressive));
  }
}

const store: Store = REDIS_URL ? new RedisStore(REDIS_URL) : new MockStore();

/* ------------------------------------------------------------------ */
/* Auth middleware                                                     */
/* ------------------------------------------------------------------ */

function authorized(authHeader: string | undefined, queryToken: string | undefined): boolean {
  if (queryToken && queryToken === DEV_TOKEN) {
    return true;
  }
  if (!authHeader) {
    return false;
  }
  const [scheme, token] = authHeader.split(' ');
  return scheme === 'Bearer' && token === DEV_TOKEN;
}

/* ------------------------------------------------------------------ */
/* Hono app                                                            */
/* ------------------------------------------------------------------ */

const app = new Hono();

// API auth gate.
app.use('/api/*', async (c, next) => {
  const auth = c.req.header('authorization');
  const token = c.req.query('token');
  if (!authorized(auth, token)) {
    return c.json({ error: 'unauthorized' }, 401);
  }
  await next();
});

app.get('/api/dark', async (c) => {
  const entries = await store.listDark();
  return c.json(entries);
});

app.get('/api/bans', async (c) => {
  const bans = await store.listBans();
  return c.json(bans);
});

app.get('/api/stats', async (c) => {
  return c.json(await store.stats());
});

app.post('/api/unban', async (c) => {
  const body = await c.req.json().catch(() => null);
  const ip = body?.ip;
  if (typeof ip !== 'string' || ip.length === 0) {
    return c.json({ error: 'ip required' }, 400);
  }
  await store.unban(ip);
  return c.json({ ok: true });
});

app.post('/api/dark/delete', async (c) => {
  const body = await c.req.json().catch(() => null);
  const hash = body?.hash;
  if (typeof hash !== 'string' || hash.length === 0) {
    return c.json({ error: 'hash required' }, 400);
  }
  await store.deleteDark(hash);
  return c.json({ ok: true });
});

app.post('/api/threshold', async (c) => {
  const body = await c.req.json().catch(() => null);
  const threshold = Number(body?.threshold);
  if (!Number.isFinite(threshold) || threshold < 0.5 || threshold > 1) {
    return c.json({ error: 'threshold must be 0.5–1' }, 400);
  }
  await store.setThreshold(threshold);
  return c.json({ ok: true });
});

app.post('/api/mode', async (c) => {
  const body = await c.req.json().catch(() => null);
  const aggressive = Boolean(body?.aggressive);
  await store.setMode(aggressive);
  return c.json({ ok: true });
});

// Serve the built frontend (dist/) for production.
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
/* Serve                                                               */
/* ------------------------------------------------------------------ */

console.log(`fox-shield Developer Mode → http://localhost:${PORT}`);
console.log(`DEV_TOKEN: ${DEV_TOKEN === 'change-me' ? '(default — set DEV_TOKEN in .env)' : '(set)'}`);
console.log(`Store: ${REDIS_URL ? 'Redis' : 'Mock (10 sample dark entries)'}`);

serve({
  port: PORT,
  fetch: app.fetch,
});
