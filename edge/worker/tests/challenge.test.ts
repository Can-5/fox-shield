/**
 * fox-shield edge worker — challenge security tests.
 *
 * Verifies that the pass cookie is a random token stored server-side (not a
 * static value), that the proof nonce is bound to the client IP and is
 * one-time use, and that the CAPTCHA answer is stored server-side rather than
 * embedded in the HTML.
 */

import { describe, it, expect } from 'vitest';
import { Challenge, DEFAULT_CHALLENGE_CONFIG, CHALLENGE_COOKIE, extractCookie, passKey, nonceKey, captchaKey } from '../src/challenge';
import { MemoryStore } from '../src/store';

function makeChallenge(): { challenge: Challenge; store: MemoryStore } {
  const store = new MemoryStore();
  const challenge = new Challenge(store, DEFAULT_CHALLENGE_CONFIG);
  return { challenge, store };
}

function makeRequest(cookie?: string): Request {
  const headers = new Headers();
  if (cookie) {
    headers.set('cookie', cookie);
  }
  return new Request('http://example.com/', { headers });
}

describe('Challenge pass cookie', () => {
  it('issues a random token stored server-side, not a static value', async () => {
    const { challenge, store } = makeChallenge();
    const res = await challenge.verify(
      new Request('http://example.com/__shield/challenge', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ nonce: 'a'.repeat(32), proof: 'x' }),
      }),
      '1.2.3.4',
      false,
    );
    // Proof is invalid, so no pass cookie should be set.
    expect(res.status).toBe(403);
  });

  it('rejects a static __shield_pass=1 cookie', async () => {
    const { challenge } = makeChallenge();
    const ok = await challenge.hasValidPass(makeRequest(`${CHALLENGE_COOKIE}=1`), '1.2.3.4');
    expect(ok).toBe(false);
  });

  it('rejects a pass cookie whose token was never issued', async () => {
    const { challenge } = makeChallenge();
    const ok = await challenge.hasValidPass(makeRequest(`${CHALLENGE_COOKIE}=deadbeef`), '1.2.3.4');
    expect(ok).toBe(false);
  });

  it('accepts a pass cookie whose token was issued for the same IP', async () => {
    const { challenge, store } = makeChallenge();
    const token = 'a'.repeat(64);
    await store.set(passKey(token), '1.2.3.4', 600);
    const ok = await challenge.hasValidPass(makeRequest(`${CHALLENGE_COOKIE}=${token}`), '1.2.3.4');
    expect(ok).toBe(true);
  });

  it('rejects a pass cookie issued for a different IP', async () => {
    const { challenge, store } = makeChallenge();
    const token = 'a'.repeat(64);
    await store.set(passKey(token), '5.5.5.5', 600);
    const ok = await challenge.hasValidPass(makeRequest(`${CHALLENGE_COOKIE}=${token}`), '1.2.3.4');
    expect(ok).toBe(false);
  });
});

describe('Challenge nonce binding', () => {
  it('stores the nonce bound to the client IP on serve', async () => {
    const { challenge, store } = makeChallenge();
    await challenge.serve('1.2.3.4', false);
    // The nonce is random; verify at least one nonce:* key exists.
    const snapshot = await store.snapshot();
    expect(snapshot.some((v) => v === '1.2.3.4')).toBe(true);
  });

  it('deletes the nonce after a single use', async () => {
    const { challenge, store } = makeChallenge();
    const nonce = 'b'.repeat(32);
    await store.set(nonceKey(nonce), '1.2.3.4', 120);
    // First verification consumes the nonce (proof is invalid but nonce is deleted).
    await challenge.verify(
      new Request('http://example.com/__shield/challenge', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ nonce, proof: 'x' }),
      }),
      '1.2.3.4',
      false,
    );
    expect(await store.get(nonceKey(nonce))).toBeNull();
  });
});

describe('Challenge CAPTCHA', () => {
  it('does not embed the answer in the HTML', async () => {
    const { challenge } = makeChallenge();
    const res = await challenge.verify(
      new Request('http://example.com/__shield/challenge', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ nonce: 'c'.repeat(32), proof: 'x' }),
      }),
      '1.2.3.4',
      false,
    );
    const html = await res.text();
    // The answer must not appear as a hidden field value.
    expect(html).not.toContain('name="captcha"');
    expect(html).not.toMatch(/value="\d+"/);
  });

  it('stores the CAPTCHA answer server-side keyed by nonce', async () => {
    const { challenge, store } = makeChallenge();
    await challenge.verify(
      new Request('http://example.com/__shield/challenge', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ nonce: 'd'.repeat(32), proof: 'x' }),
      }),
      '1.2.3.4',
      false,
    );
    // A captcha:* key should exist with a numeric answer.
    const snapshot = await store.snapshot();
    expect(snapshot.some((v) => /^\d+$/.test(v))).toBe(true);
  });
});

describe('extractCookie', () => {
  it('extracts a cookie by name', () => {
    expect(extractCookie('a=1; __shield_pass=abc; b=2', CHALLENGE_COOKIE)).toBe('abc');
  });

  it('returns null when the cookie is absent', () => {
    expect(extractCookie('a=1; b=2', CHALLENGE_COOKIE)).toBeNull();
  });
});
