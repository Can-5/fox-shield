/**
 * fox-shield edge worker — rate limiter tests.
 *
 * Verifies the sliding-window limiter: normal 20 rps / burst 40, aggressive
 * 10 rps / burst 20, 429 with Retry-After on over-limit, and immediate ban on
 * burst breach (the 753 rps scenario).
 */

import { describe, it, expect } from 'vitest';
import { RateLimiter, DEFAULT_LIMITER_CONFIG } from '../src/limiter';
import { MemoryStore, banKey } from '../src/store';

function makeLimiter(): { limiter: RateLimiter; store: MemoryStore } {
  const store = new MemoryStore();
  const limiter = new RateLimiter(store, DEFAULT_LIMITER_CONFIG);
  return { limiter, store };
}

describe('RateLimiter (normal mode)', () => {
  it('allows requests within the 20 rps budget', async () => {
    const { limiter } = makeLimiter();
    for (let i = 0; i < 20; i++) {
      const res = await limiter.allow('1.2.3.4', false);
      expect(res.ok).toBe(true);
    }
  });

  it('rejects with 429 when exceeding 20 rps', async () => {
    const { limiter } = makeLimiter();
    for (let i = 0; i < 20; i++) {
      await limiter.allow('1.2.3.4', false);
    }
    const res = await limiter.allow('1.2.3.4', false);
    expect(res.ok).toBe(false);
    expect(res.retryAfter).toBeGreaterThanOrEqual(1);
  });

  it('bans after repeated violations', async () => {
    const { limiter, store } = makeLimiter();
    // Exhaust the budget.
    for (let i = 0; i < 20; i++) {
      await limiter.allow('1.2.3.4', false);
    }
    // Trigger 3 violations -> ban.
    for (let i = 0; i < 3; i++) {
      await limiter.allow('1.2.3.4', false);
    }
    expect(await store.get(banKey('1.2.3.4'))).not.toBeNull();
  });

  it('bans immediately on burst breach (753 rps scenario)', async () => {
    const { limiter, store } = makeLimiter();
    // 753 rps: exceed the 40 burst cap instantly.
    for (let i = 0; i < 40; i++) {
      await limiter.allow('9.9.9.9', false);
    }
    const res = await limiter.allow('9.9.9.9', false);
    expect(res.ok).toBe(false);
    expect(await store.get(banKey('9.9.9.9'))).not.toBeNull();
  });
});

describe('RateLimiter (aggressive mode)', () => {
  it('allows only 10 rps in aggressive mode', async () => {
    const { limiter } = makeLimiter();
    for (let i = 0; i < 10; i++) {
      const res = await limiter.allow('5.5.5.5', true);
      expect(res.ok).toBe(true);
    }
    const res = await limiter.allow('5.5.5.5', true);
    expect(res.ok).toBe(false);
  });

  it('bans on aggressive burst breach (20)', async () => {
    const { limiter, store } = makeLimiter();
    for (let i = 0; i < 20; i++) {
      await limiter.allow('6.6.6.6', true);
    }
    const res = await limiter.allow('6.6.6.6', true);
    expect(res.ok).toBe(false);
    expect(await store.get(banKey('6.6.6.6'))).not.toBeNull();
  });
});
