/**
 * fox-shield edge worker — main fetch handler.
 *
 * Middleware chain (mirrors cmd/shield/main.go):
 *
 *   limiter -> waf -> similarity -> challenge -> destroy -> origin fetch
 *
 * Env:
 *   SHIELD_KV       KV namespace binding (optional; in-memory fallback in dev)
 *   AGGRESSIVE_MODE "true"/"false" — tightens limits, thresholds and challenge
 *   ORIGIN_URL      upstream origin base URL
 */

import type { Store } from './store';
import { createStore, banKey } from './store';
import { RateLimiter } from './limiter';
import { Waf } from './waf';
import { SimilarityDetector, normalizeRequest, fnv1a } from './similarity';
import { Challenge } from './challenge';
import { Destroyer } from './destroy';

export interface Env {
  SHIELD_KV?: KVNamespace;
  AGGRESSIVE_MODE?: string;
  ORIGIN_URL?: string;
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

function bannedPage(ip: string, reason: string, req: Request): string {
  const isHack = reason.includes('unlimited') || reason.includes('waf') || reason.includes('similarity');
  const detail = isHack ? 'hacklemeye çalıştınız' : reason;
  const ua = req.headers.get('user-agent') ?? 'unknown';
  const lang = req.headers.get('accept-language') ?? 'unknown';
  const ref = req.headers.get('referer') ?? '—';
  const cfRay = req.headers.get('cf-ray') ?? '—';
  const cfAsn = (req as any).cf?.asn ?? req.headers.get('cf-asn') ?? '—';
  const colo = (req as any).cf?.colo ?? '—';
  const country = req.headers.get('cf-ipcountry') ?? (req as any).cf?.country ?? 'unknown';
  const method = req.method;
  const path = new URL(req.url).pathname + new URL(req.url).search;
  const time = new Date().toISOString();
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>you are banned ha ha ha</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0e14;color:#e5e7eb;font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial} .card{background:#1f2937;border:1px solid #2d3748;border-radius:12px;padding:28px;max-width:680px;width:94%;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.5)} h1{font-size:32px;margin:0 0 8px;color:#f6821f} p{color:#9aa3b2;margin:6px 0;font-size:14px} code{background:#0b0e14;padding:2px 6px;border-radius:4px;color:#f87171;word-break:break-all} table{width:100%;margin:14px 0;border-collapse:collapse;font-size:13px} td{padding:6px 8px;border:1px solid #2d3748;text-align:left} td:first-child{color:#9aa3b2;width:160px} a{color:#7fb3ff} .idiot{margin-top:14px;font-size:22px;color:#f87171;font-weight:800;animation:flash 0.5s infinite alternate} @keyframes flash{from{opacity:1;transform:scale(1)}to{opacity:0.3;transform:scale(1.05)}} .ip-big{font-size:20px;color:#f87171;font-weight:800;animation:pulse 1s infinite} @keyframes pulse{0%{text-shadow:0 0 0 #f87171}50%{text-shadow:0 0 12px #f87171}100%{text-shadow:0 0 0 #f87171}}</style></head><body><div class="card"><h1>you are banned ha ha ha 😂</h1><div class="idiot">you are an idiot ☠️</div><p>Sebep: <code>${detail}</code></p><p>fox-shield seni yakaladı — hacklemeye çalıştınız</p><table><tr><td>IP (senin)</td><td><code class="ip-big">${ip}</code></td></tr><tr><td>Ülke / Colo / ASN</td><td>${country} / ${colo} / ${cfAsn}</td></tr><tr><td>Zaman</td><td>${time}</td></tr><tr><td>İstek</td><td><code>${method} ${path}</code></td></tr><tr><td>User-Agent</td><td style="word-break:break-all">${ua}</td></tr><tr><td>Accept-Language</td><td>${lang}</td></tr><tr><td>Referer</td><td style="word-break:break-all">${ref}</td></tr><tr><td>CF-Ray</td><td>${cfRay}</td></tr><tr><td>Sebep detayı</td><td><code>${reason}</code></td></tr></table><p><a href="/idiot.html" target="_blank">you are an idiot — harmless flashing page (bizim host)</a> • <a href="https://www.youtube.com/watch?v=dQw4w9WgXcQ" target="_blank" rel="noopener">YouTube meme</a></p><audio autoplay loop><source src="data:audio/wav;base64,UklGRigAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQQAAAAAAA==" type="audio/wav"></audio><p style="font-size:12px;color:#6b7280;margin-top:12px">IP kalıcı olarak engellendi (unlimited). Yukarıdaki veriler sadece senin isteğinden görülenler. İtiraz için admin.</p></div><script>try{const ctx=new (window.AudioContext||window.webkitAudioContext)();const o=ctx.createOscillator();o.type='square';o.frequency.value=440;o.connect(ctx.destination);o.start();setTimeout(()=>o.stop(),400);}catch(e){}</script></body></html>`;
}
function forbidden(ip: string, reason: string, req: Request): Response {
  return new Response(bannedPage(ip, reason, req), {
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

    if (url.pathname === '/idiot.html') {
      return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>you are an idiot</title><style>html,body{margin:0;height:100%;background:#000;color:#fff;display:flex;align-items:center;justify-content:center;font-family:monospace;overflow:hidden}h1{font-size:48px;animation:flash .2s infinite alternate} @keyframes flash{from{background:#000;color:#fff}to{background:#fff;color:#000}} .box{text-align:center}</style></head><body><div class="box"><h1>you are an idiot 😂</h1><p>harmless meme — no virus</p><p><a href="/" style="color:#7fb3ff">← geri</a></p></div><script>let c=0;setInterval(()=>{document.body.style.transform=c%2?'translate(2px,2px)':'translate(0,0)';c++},100)</script></body></html>`, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    }
    // Challenge endpoint is served directly (GET page / POST verify).
    if (url.pathname === '/__shield/challenge') {
      if (request.method === 'POST') {
        return challenge.verify(request, ip, aggressive);
      }
      return challenge.serve(ip, aggressive);
    }

    // Banned IPs are rejected outright.
    const banReason = await store.get(banKey(ip));
    if (banReason !== null) {
      return forbidden(ip, banReason, request);
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
      await waf.block(ip, hash, normalized, wafMatch);
      const r = wafMatch.id ? `unlimited:waf:${wafMatch.id}:${wafMatch.category}` : 'waf:oversized-body';
      return forbidden(ip, r, request);
    }

    // 3. Similarity.
    const similar = await similarity.check(ip, normalized, aggressive);
    if (similar) {
      const r = (await store.get(banKey(ip))) ?? 'unlimited:similarity match';
      return forbidden(ip, r, request);
    }

    // 4. Challenge — only for suspicious requests without a valid pass cookie.
    const hasPass = await challenge.hasValidPass(request, ip);
    if (limit.suspicious && !hasPass) {
      return challenge.serve(ip, aggressive);
    }

    // 5. Destroy fallback — flagged malicious but not banned (race condition).
    const flagged = wafMatch !== null || similar;
    const destroyed = await destroyer.destroy(ip, flagged);
    if (destroyed) {
      return destroyed;
    }

    // 6. Origin fetch — fallback to landing page if origin unreachable (prevents 1101).
    const originBase = env.ORIGIN_URL ?? 'http://127.0.0.1:3000';
    const isPlaceholder = originBase.includes('your-origin.example.com') || originBase.includes('127.0.0.1');
    if (isPlaceholder && url.pathname === '/') {
      return new Response(
        `<!doctype html><html><head><meta charset="utf-8"><title>fox-shield — live</title><style>body{font-family:system-ui;background:#0b0e14;color:#e5e7eb;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0} .c{background:#1f2937;border:1px solid #2d3748;border-radius:12px;padding:32px;max-width:520px;text-align:center} a{color:#f6821f}</style></head><body><div class="c"><h1>🦊 fox-shield — Edge Live</h1><p>Worker çalışıyor. Dashboard: <a href="https://be9263d0.fox-shield.pages.dev">be9263d0.fox-shield.pages.dev</a></p><p>Challenge: <a href="/__shield/challenge">/__shield/challenge</a></p><p style="color:#9aa3b2;font-size:13px">ORIGIN_URL ayarla → Worker origin'e proxy'ler. Şu an placeholder.</p></div></body></html>`,
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
