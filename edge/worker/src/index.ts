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
import { Challenge, CHALLENGE_COOKIE } from './challenge';
import { Destroyer } from './destroy';

export interface Env {
  SHIELD_KV?: KVNamespace;
  AGGRESSIVE_MODE?: string;
  ORIGIN_URL?: string;
}

/** Extracts the client IP, honoring CF-Connecting-IP then X-Forwarded-For. */
export function clientIp(request: Request): string {
  const cf = request.headers.get('CF-Connecting-IP');
  if (cf && cf.trim() !== '') {
    return cf.trim();
  }
  const xff = request.headers.get('X-Forwarded-For');
  if (xff) {
    const first = xff.split(',')[0];
    if (first && first.trim() !== '') {
      return first.trim();
    }
  }
  return 'unknown';
}

/** Reads the request body as text (empty for GET/HEAD). */
async function readBody(request: Request): Promise<string> {
  if (request.method === 'GET' || request.method === 'HEAD') {
    return '';
  }
  try {
    return await request.text();
  } catch {
    return '';
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

/** Returns a 403 response with the given message. */
function forbidden(message: string): Response {
  return new Response(message, {
    status: 403,
    headers: { 'content-type': 'text/plain; charset=utf-8' },
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
    const challenge = new Challenge();
    const destroyer = new Destroyer(store);

    const url = new URL(request.url);
    const ip = clientIp(request);

    // Challenge endpoint is served directly (GET page / POST verify).
    if (url.pathname === '/__shield/challenge') {
      if (request.method === 'POST') {
        return challenge.verify(request, ip, aggressive);
      }
      return challenge.serve(ip, aggressive);
    }

    // Banned IPs are rejected outright.
    if ((await store.get(banKey(ip))) !== null) {
      return forbidden('Blocked');
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
    const body = await readBody(request);
    const normalized = normalizeRequest(request.method, url.pathname, url.searchParams, body);
    const hash = fnv1a(normalized);

    // 2. WAF.
    const wafMatch = waf.match(request.method, url.pathname, url.search, body);
    if (wafMatch) {
      await waf.block(ip, hash, normalized, wafMatch);
      return forbidden('Blocked by WAF');
    }

    // 3. Similarity.
    const similar = await similarity.check(ip, normalized, aggressive);
    if (similar) {
      return forbidden('Blocked');
    }

    // 4. Challenge — only for suspicious requests without a valid pass cookie.
    const hasPass = request.headers.get('cookie')?.includes(`${CHALLENGE_COOKIE}=1`) ?? false;
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
