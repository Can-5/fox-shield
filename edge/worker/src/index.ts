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

    // 6. Origin fetch.
    const originBase = env.ORIGIN_URL ?? 'http://127.0.0.1:3000';
    const originRequest = buildOriginRequest(request, originBase, url.pathname, url.search, body);
    return fetch(originRequest);
  },
};
