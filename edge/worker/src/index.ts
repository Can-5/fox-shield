/**
 * fox-shield edge worker  main fetch handler.
 *
 * Middleware chain (mirrors cmd/shield/main.go):
 *
 *   limiter -> waf -> similarity -> challenge -> destroy -> origin fetch
 *
 * Env:
 *   SHIELD_KV       KV namespace binding (optional; in-memory fallback in dev)
 *   AGGRESSIVE_MODE "true"/"false"  tightens limits, thresholds and challenge
 *   ORIGIN_URL      upstream origin base URL
 */

import type { Store } from './store';
import { createStore, banKey, deviceKey, subnetBanKey, offenseKey, ipVaultKey } from './store';
import { RateLimiter } from './limiter';
import { Waf } from './waf';
import { SimilarityDetector, normalizeRequest, fnv1a } from './similarity';
import { Challenge } from './challenge';
import { Destroyer } from './destroy';
import { hashIP, subnetHash, subnetOf, deviceHash, maskIp, resolveSalt, vaultDecrypt } from './hash';

export interface Env {
  SHIELD_KV?: KVNamespace;
  AGGRESSIVE_MODE?: string;
  ORIGIN_URL?: string;
  /** Salt used to hash IPs / encrypt the raw-IP vault. Falls back to a KV-stored
   * daily salt, then a dev default. */
  IP_SALT?: string;
  /** DevMode admin token required for /api/raw-ips. */
  DEV_TOKEN?: string;
}

/**
 * Extracts the client IP.
 *
 * On Cloudflare Workers, CF-Connecting-IP is set by Cloudflare's edge and is
 * trustworthy (it cannot be spoofed by the client). X-Forwarded-For is only
 * used as a fallback when CF-Connecting-IP is absent (e.g. local dev), and is
 * NOT trusted when the worker is deployed behind Cloudflare because the
 * attacker controls it. The Go origin uses a separate, env-gated extractor
 * (internal/ip) because it may be exposed directly.
 *
 * The returned address is normalized: IPv6 zone identifiers are stripped and
 * the address is lowercased so it can be used as a stable rate-limit / ban key.
 */
export function clientIp(request: Request): string {
  let raw = '';
  const cf = request.headers.get('CF-Connecting-IP');
  if (cf && cf.trim() !== '') {
    raw = cf.trim();
  } else {
    const xff = request.headers.get('X-Forwarded-For');
    if (xff) {
      const first = xff.split(',')[0];
      if (first && first.trim() !== '') {
        raw = first.trim();
      }
    }
  }
  if (raw === '') {
    return 'unknown';
  }
  return normalizeIp(raw);
}

/**
 * Normalizes an IP address for use as a key: strips an IPv6 zone identifier
 * ("fe80::1%eth0" -> "fe80::1") and lowercases the address.
 */
export function normalizeIp(addr: string): string {
  const zone = addr.indexOf('%');
  const clean = zone >= 0 ? addr.slice(0, zone) : addr;
  return clean.toLowerCase();
}

/** KV key under which a generated daily salt is stored (fallback when IP_SALT
 * is not set). */
const SALT_KEY = 'salt:daily';

/**
 * Resolves the IP-hashing salt. Priority:
 *   1. IP_SALT env var (production).
 *   2. A KV-stored salt (set once, reused across requests).
 *   3. A freshly generated daily salt, persisted to KV so all workers agree.
 * The salt is the secret that makes the hashes non-reversible; it must be set
 * in production and rotated carefully.
 */
async function resolveIpSalt(store: Store, envSalt?: string): Promise<string> {
  const explicit = resolveSalt(envSalt);
  if (envSalt && envSalt.trim() !== '') {
    return explicit;
  }
  const stored = await store.get(SALT_KEY);
  if (stored && stored.trim() !== '') {
    return stored;
  }
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const daily = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  await store.set(SALT_KEY, daily, 24 * 60 * 60);
  return daily;
}

/** Builds the device fingerprint from the request's ambient headers. */
function requestDeviceHash(req: Request): string {
  const ua = req.headers.get('user-agent') ?? '';
  const lang = (req.headers.get('accept-language') ?? '').toLowerCase();
  const country = req.headers.get('cf-ipcountry') ?? (req as any).cf?.country ?? '';
  const colo = (req as any).cf?.colo ?? '';
  return deviceHash(ua, lang, country, colo);
}

/** Human-readable subnet prefix for display on the banned page. */
function subnetOfLabel(ip: string): string {
  return subnetOf(ip) ?? '';
}

/**
 * DevMode admin endpoint: recovers the encrypted raw IPs stored in the vault.
 * Requires a valid DEV_TOKEN (Bearer) and a bound device (X-Device-Id). Returns
 * only the vault entries (raw:{hash} -> decrypted IP), never the ban list, so
 * the raw addresses stay out of the ban keys and out of logs.
 */
async function rawIpsEndpoint(
  request: Request,
  env: Env,
  store: Store,
  salt: string,
): Promise<Response> {
  const token = request.headers.get('authorization') ?? '';
  const device = request.headers.get('x-device-id') ?? '';
  const expected = env.DEV_TOKEN ?? '';
  if (expected === '' || token !== `Bearer ${expected}` || device === '') {
    return new Response('Unauthorized', { status: 401 });
  }
  // The vault is keyed by ipvault:{hash}; we cannot enumerate KV, so we only
  // support a lookup by the caller-provided hash. This keeps raw IPs out of any
  // enumerable index.
  const url = new URL(request.url);
  const hash = url.searchParams.get('hash');
  if (!hash) {
    return new Response(JSON.stringify({ error: 'missing ?hash=' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
  }
  const payload = await store.get(ipVaultKey(hash));
  if (payload === null) {
    return new Response(JSON.stringify({ error: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  }
  const raw = await vaultDecrypt(payload, salt);
  if (raw === null) {
    return new Response(JSON.stringify({ error: 'decrypt failed' }), {
      status: 500,
      headers: { 'content-type': 'application/json' },
    });
  }
  return new Response(JSON.stringify({ hash, ip: raw }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

/** Reads the request body as text (empty for GET/HEAD). */
async function readBody(request: Request): Promise<{ body: string; oversized: boolean }> {
  if (request.method === 'GET' || request.method === 'HEAD') {
    return { body: '', oversized: false };
  }
  try {
    const body = await request.text();
    return { body, oversized: body.length > 1 << 20 };
  } catch {
    return { body: '', oversized: false };
  }
}

/** Builds a fresh Request for the origin, preserving method/headers/body. */
function buildOriginRequest(
  original: Request,
  originBase: string,
  pathname: string,
  search: string,
  body: string,
): Request {
  const origin = new URL(originBase);
  origin.pathname = pathname;
  origin.search = search;

  const headers = new Headers(original.headers);
  // Strip hop-by-hop / shield-internal headers.
  headers.delete('cf-connecting-ip');
  headers.delete('cf-ray');
  headers.delete('cf-visitor');
  headers.delete('cf-ipcountry');
  headers.delete('cf-worker');

  const init: RequestInit = {
    method: original.method,
    headers,
    redirect: 'manual',
  };
  if (body !== '') {
    init.body = body;
  }
  return new Request(origin.toString(), init);
}

function bannedPage(maskedIp, deviceHashShort, offenseCount, subnet, reason, req){
  const fp = (deviceHashShort||'').padEnd(8,'*') + '........'.slice(0,8);
  const incident = 'FX-' + Math.random().toString(16).slice(2,8).toUpperCase();
  const risk = isNaN(Number(offenseCount)) ? 98 : Math.min(98, 70+Number(offenseCount)*10);
  const duration = reason.includes('unlimited') ? 'PERMANENT' : '10 MINUTES';
  const action = (reason.includes('device')||reason.includes('similarity')) ? 'DEVICE BLOCK' : 'IP BLOCK';
  const title = 'FOXAI SECURITY - BLOCKED';
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0e14;color:#e5e7eb;font-family:ui-monospace,Menlo,Consolas,monospace} .box{line-height:1.4;font-size:14px;white-space:pre} a{color:#7fb3ff}</style></head><body><div class="box">╔══════════════════════════════════════════╗
║             FOXAI SECURITY            ║
╠══════════════════════════════════════════╣
║                                          ║
║          ACCESS TEMPORARILY BLOCKED      ║
║                                          ║
║  Suspicious activity was detected.       ║
║                                          ║
║  Risk Score:        ${String(risk).padEnd(3)} / 100             ║
║  Incident ID:       ${incident}             ║
║  Action:            ${action.padEnd(16)}║
║  Duration:          ${duration.padEnd(16)}║
║                                          ║
║  Source Fingerprint:                     ║
║  ${fp.padEnd(34)}║
║                                          ║
║  No personal information is displayed.   ║
║  Security event has been recorded.       ║
║                                          ║
║          FOXAI SECURITY SYSTEM            ║
║                                          ║
╚══════════════════════════════════════════╝
</div><div style="text-align:center;margin:16px 0;font-size:22px;font-weight:900;color:#f87171">DURATION: 30 MINUTES — auto decided</div><p style="text-align:center"><a href="/idiot.html">you are an idiot - harmless</a> | <a href="https://github.com/Can-5/fox-shield">fox-shield</a></p></body></html>`;
}
function forbidden(
  maskedIp: string,
  deviceHashShort: string,
  offenseCount: number,
  subnet: string,
  reason: string,
  req: Request,
): Response {
  return new Response(bannedPage(maskedIp, deviceHashShort, offenseCount, subnet, reason, req), {
    status: 403,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const store: Store = createStore(env.SHIELD_KV);
    const aggressive = env.AGGRESSIVE_MODE === 'true';

    const limiter = new RateLimiter(store);
    const waf = new Waf(store);
    const similarity = new SimilarityDetector(store);
    const challenge = new Challenge(store);
    const destroyer = new Destroyer(store);

    const url = new URL(request.url);
    const ip = clientIp(request);

    // Resolve the salt and derive the privacy-preserving identifiers. The raw
    // IP is only ever used to compute these hashes and to encrypt the vault
    // entry  it is never a KV key and never logged.
    const salt = await resolveIpSalt(store, env.IP_SALT);
    const ipHash = await hashIP(ip, salt);
    const devHash = requestDeviceHash(request);
    const subHash = await subnetHash(ip, salt);
    const masked = maskIp(ip);
    const subnetLabel = subHash !== null ? (await subnetOfLabel(ip)) : '';

    // DevMode admin endpoint: recover encrypted raw IPs. Requires DEV_TOKEN and
    // a bound device (X-Device-Id). Returns only the vault entries, never the
    // ban list.
    if (url.pathname === '/api/raw-ips') {
      return rawIpsEndpoint(request, env, store, salt);
    }

    if (url.pathname === '/idiot.html') {
      return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>you are an idiot</title><style>html,body{margin:0;height:100%;overflow:hidden;background:#000;font-family:monospace} .bg{position:fixed;inset:0;display:grid;grid-template-columns:repeat(3,1fr);grid-template-rows:repeat(3,1fr);gap:8px;padding:8px} .cell{display:flex;align-items:center;justify-content:center;font-weight:900;font-size:18px;border:3px solid #fff;animation:flash .15s infinite alternate,shake .1s infinite} @keyframes flash{from{background:#000;color:#fff;transform:rotate(-1deg)}to{background:#fff;color:#000;transform:rotate(1deg)}} @keyframes shake{0%{transform:translate(0,0)}25%{transform:translate(3px,3px)}50%{transform:translate(-3px,2px)}75%{transform:translate(2px,-2px)}} marquee{position:fixed;bottom:0;width:100%;background:#f00;color:#fff;padding:6px;font-weight:900;z-index:10} .center{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none} .center h1{font-size:42px;background:#f6821f;color:#000;padding:12px 20px;border:4px solid #fff;animation:pulse .3s infinite} @keyframes pulse{0%{transform:scale(1)}50%{transform:scale(1.1)}} a{position:fixed;top:10px;right:10px;z-index:20;background:#1f2937;color:#fff;padding:8px 12px;border-radius:6px;text-decoration:none;border:1px solid #2d3748}</style></head><body><div class="bg"><div class="cell">you are an idiot</div><div class="cell" style="animation-delay:.05s">HA HA HA</div><div class="cell" style="animation-delay:.1s">you are banned</div><div class="cell" style="animation-delay:.03s">  </div><div class="cell" style="animation-delay:.07s">fox-shield</div><div class="cell" style="animation-delay:.12s">idiot idiot idiot</div><div class="cell" style="animation-delay:.02s">GET REKT</div><div class="cell" style="animation-delay:.09s">LOL LOL LOL</div><div class="cell" style="animation-delay:.11s">you are an idiot</div></div><div class="center"><h1>you are an idiot </h1></div><marquee>you are banned ha ha ha  hacklemeye altnz  fox-shield  you are an idiot  you are banned ha ha ha </marquee><a href="/"> KAPAT</a><audio autoplay loop><source src="data:audio/wav;base64,UklGRigAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQQAAAAAAA=="></audio><script>let n=0;setInterval(()=>{document.title=n%2?'you are an idiot':'you are banned ha ha ha';n++},200);try{const a=new (window.AudioContext||window.webkitAudioContext)();setInterval(()=>{const o=a.createOscillator();o.type='square';o.frequency.value=300+Math.random()*400;o.connect(a.destination);o.start();setTimeout(()=>o.stop(),120)},300)}catch(e){} document.addEventListener('click',()=>location.href='/');</script></body></html>`, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    }
    // Challenge endpoint is served directly (GET page / POST verify).
    if (url.pathname === '/__shield/challenge') {
      if (request.method === 'POST') {
        return challenge.verify(request, ip, aggressive);
      }
      return challenge.serve(ip, aggressive);
    }

    // Banned IPs / devices / subnets are rejected outright. We check the hashed
    // IP, the device fingerprint and the subnet hash  never the raw IP.
    const banReason =
      (await store.get(banKey(ipHash))) ??
      (await store.get(deviceKey(devHash))) ??
      (subHash !== null ? await store.get(subnetBanKey(subHash)) : null);
    if (banReason !== null) {
      const offenseRaw = await store.get(offenseKey(ipHash));
      const offenseCount = offenseRaw ? Number.parseInt(offenseRaw, 10) || 0 : 0;
      return forbidden(masked, devHash.slice(0, 8), offenseCount, subnetLabel, banReason, request);
    }

    // 1. Rate limiter.
    const limit = await limiter.allow(ip, aggressive);
    if (!limit.ok) {
      return new Response('Too Many Requests', {
        status: 429,
        headers: {
          'retry-after': String(limit.retryAfter),
          'content-type': 'text/plain; charset=utf-8',
        },
      });
    }

    // Read the body once; reused by WAF, similarity and the origin request.
    const { body, oversized } = await readBody(request);
    const normalized = normalizeRequest(request.method, url.pathname, url.searchParams, body);
    const hash = fnv1a(normalized);

    // 2. WAF.
    const wafMatch = waf.match(request.method, url.pathname, url.search, body, request.headers, oversized);
    if (wafMatch) {
      await waf.block(ipHash, devHash, subHash, ip, salt, hash, normalized, wafMatch, aggressive);
      const r = wafMatch.id ? `unlimited:waf:${wafMatch.id}:${wafMatch.category}` : 'waf:oversized-body';
      const offenseRaw = await store.get(offenseKey(ipHash));
      const offenseCount = offenseRaw ? Number.parseInt(offenseRaw, 10) || 0 : 0;
      return forbidden(masked, devHash.slice(0, 8), offenseCount, subnetLabel, r, request);
    }

    // 3. Similarity.
    const similar = await similarity.check(ipHash, devHash, subHash, ip, salt, normalized, aggressive);
    if (similar) {
      const r = (await store.get(banKey(ipHash))) ?? 'unlimited:similarity match';
      const offenseRaw = await store.get(offenseKey(ipHash));
      const offenseCount = offenseRaw ? Number.parseInt(offenseRaw, 10) || 0 : 0;
      return forbidden(masked, devHash.slice(0, 8), offenseCount, subnetLabel, r, request);
    }

    // 4. Challenge  only for suspicious requests without a valid pass cookie.
    const hasPass = await challenge.hasValidPass(request, ip);
    if (limit.suspicious && !hasPass) {
      return challenge.serve(ip, aggressive);
    }

    // 5. Destroy fallback  flagged malicious but not banned (race condition).
    const flagged = wafMatch !== null || similar;
    const destroyed = await destroyer.destroy(ipHash, flagged);
    if (destroyed) {
      return destroyed;
    }

    // 6. Origin fetch  fallback to landing page if origin unreachable (prevents 1101).
    const originBase = env.ORIGIN_URL ?? 'http://127.0.0.1:3000';
    const isPlaceholder = originBase.includes('your-origin.example.com') || originBase.includes('127.0.0.1');
    if (isPlaceholder && url.pathname === '/') {
      return new Response(
        `<!doctype html><html><head><meta charset="utf-8"><title>fox-shield  live</title><style>body{font-family:system-ui;background:#0b0e14;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0} .c{background:#1f2937;border:1px solid #2d3748;border-radius:12px;padding:32px;max-width:520px;text-align:center} a{color:#f6821f}</style></head><body><div class="c"><h1> fox-shield  Edge Live</h1><p>Worker alyor. Dashboard: <a href="https://be9263d0.fox-shield.pages.dev">be9263d0.fox-shield.pages.dev</a></p><p>Challenge: <a href="/__shield/challenge">/__shield/challenge</a></p><p style="color:#9aa3b2;font-size:13px">ORIGIN_URL ayarla  Worker origin'e proxy'ler. u an placeholder.</p></div></body></html>`,
        { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } },
      );
    }
    const originRequest = buildOriginRequest(request, originBase, url.pathname, url.search, body);
      try {
        return await fetch(originRequest);
      } catch (e) {
        return new Response(`Origin unreachable: ${String(e)}`, {
          status: 502,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      }
    } catch (e) {
      return new Response(`Worker error: ${String(e)}\n${(e as Error)?.stack ?? ''}`, {
        status: 500,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }
  },
};
