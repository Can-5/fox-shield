/**
 * fox-shield edge worker — regression tests.
 *
 * Guards against re-introduction of previously fixed security issues:
 *   - a static / forged pass cookie must be rejected
 *   - a proof nonce must be one-time use (replay rejected)
 *   - the CAPTCHA answer must never be embedded in the HTML
 *   - the WAF must catch payloads smuggled in request headers
 *   - an oversized request body must be blocked
 *
 * The Go-side spoof-resistant ClientIP (XFF must not bypass when
 * TRUSTED_PROXY != 1) is covered by internal/ip/ip_test.go.
 */

import { describe, it, expect } from 'vitest';
import { Challenge, DEFAULT_CHALLENGE_CONFIG, CHALLENGE_COOKIE, passKey, nonceKey } from '../src/challenge';
import { Waf } from '../src/waf';
import { MemoryStore } from '../src/store';

function makeChallenge(): { challenge: Challenge; store: MemoryStore } {
  const store = new MemoryStore();
  const challenge = new Challenge(store, DEFAULT_CHALLENGE_CONFIG);
  return { challenge, store };
}

function jsonVerify(challenge: Challenge, nonce: string, proof: string, ip: string): Promise<Response> {
  return challenge.verify(
    new Request('http://example.com/__shield/challenge', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce, proof }),
    }),
    ip,
    false,
  );
}

describe('regression: static pass cookie must be rejected', () => {
  it('rejects a hardcoded __shield_pass=1 cookie', async () => {
    const { challenge } = makeChallenge();
    const req = new Request('http://example.com/', {
      headers: { cookie: `${CHALLENGE_COOKIE}=1` },
    });
    expect(await challenge.hasValidPass(req, '1.2.3.4')).toBe(false);
  });

  it('rejects a cookie whose token was never issued', async () => {
    const { challenge } = makeChallenge();
    const req = new Request('http://example.com/', {
      headers: { cookie: `${CHALLENGE_COOKIE}=deadbeef` },
    });
    expect(await challenge.hasValidPass(req, '1.2.3.4')).toBe(false);
  });
});

describe('regression: nonce replay must be rejected', () => {
  it('rejects a second use of the same nonce', async () => {
    const { challenge, store } = makeChallenge();
    const nonce = 'f'.repeat(32);
    await store.set(nonceKey(nonce), '1.2.3.4', 120);

    // First use consumes the nonce (proof is invalid but the nonce is deleted).
    await jsonVerify(challenge, nonce, 'x', '1.2.3.4');
    expect(await store.get(nonceKey(nonce))).toBeNull();

    // Replay: the nonce no longer exists, so it must be rejected.
    const replay = await jsonVerify(challenge, nonce, 'x', '1.2.3.4');
    expect(replay.status).toBe(403);
  });

  it('rejects a nonce bound to a different IP', async () => {
    const { challenge, store } = makeChallenge();
    const nonce = 'e'.repeat(32);
    await store.set(nonceKey(nonce), '5.5.5.5', 120);
    const res = await jsonVerify(challenge, nonce, 'x', '1.2.3.4');
    expect(res.status).toBe(403);
  });
});

describe('regression: CAPTCHA answer must not be in the HTML', () => {
  it('does not embed the numeric answer as a hidden field', async () => {
    const { challenge } = makeChallenge();
    const res = await jsonVerify(challenge, 'd'.repeat(32), 'x', '1.2.3.4');
    const html = await res.text();
    expect(html).not.toMatch(/value="\d+"/);
    expect(html).not.toContain('name="answer" value="');
  });
});

describe('regression: WAF must catch header payloads', () => {
  it('catches a SQLi payload in the User-Agent header', () => {
    const waf = new Waf(new MemoryStore());
    const headers = new Headers({ 'user-agent': "union select username,password from users" });
    const m = waf.match('GET', '/', '', '', headers);
    expect(m).not.toBeNull();
    expect(m?.category).toBe('sqli');
  });

  it('catches an XSS payload in a custom X- header', () => {
    const waf = new Waf(new MemoryStore());
    const headers = new Headers({ 'x-custom': '<script>alert(1)</script>' });
    const m = waf.match('GET', '/', '', '', headers);
    expect(m).not.toBeNull();
    expect(m?.category).toBe('xss');
  });
});

describe('regression: oversized body must be blocked', () => {
  it('flags a body larger than the scan cap as oversized', () => {
    const waf = new Waf(new MemoryStore());
    const big = 'a'.repeat((1 << 20) + 1);
    const m = waf.match('POST', '/upload', '', big, undefined, true);
    expect(m).not.toBeNull();
    expect(m?.oversizedBody).toBe(true);
  });
});
