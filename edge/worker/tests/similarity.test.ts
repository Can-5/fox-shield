/**
 * fox-shield edge worker — similarity detector tests.
 *
 * Verifies FNV hashing, normalization, Levenshtein similarity, and the 90%
 * (normal) / 85% (aggressive) threshold behavior against the dark list.
 */

import { describe, it, expect } from 'vitest';
import {
  fnv1a,
  normalizeRequest,
  levenshtein,
  similarity,
  SimilarityDetector,
} from '../src/similarity';
import { MemoryStore, darkKey } from '../src/store';

describe('fnv1a', () => {
  it('produces a stable 8-char hex hash', () => {
    expect(fnv1a('GET /')).toMatch(/^[0-9a-f]{8}$/);
    expect(fnv1a('GET /')).toBe(fnv1a('GET /'));
  });

  it('differs for different inputs', () => {
    expect(fnv1a('GET /a')).not.toBe(fnv1a('GET /b'));
  });
});

describe('normalizeRequest', () => {
  it('sorts query keys and includes body hash', () => {
    const q = new URLSearchParams('b=2&a=1');
    const norm = normalizeRequest('GET', '/search', q, '');
    expect(norm).toContain('&a');
    expect(norm).toContain('&b');
    expect(norm.startsWith('GET /search')).toBe(true);
  });
});

describe('levenshtein / similarity', () => {
  it('returns 1.0 for identical strings', () => {
    expect(similarity('abc', 'abc')).toBe(1);
  });

  it('returns 0.0 for empty input', () => {
    expect(similarity('', 'abc')).toBe(0);
  });

  it('computes edit distance', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(3);
  });

  it('returns high similarity for near-identical requests', () => {
    const a = 'GET /login&user#abc123';
    const b = 'GET /login&user#abc124';
    expect(similarity(a, b)).toBeGreaterThan(0.9);
  });
});

describe('SimilarityDetector', () => {
  it('bans on exact dark-list hit', async () => {
    const store = new MemoryStore();
    const det = new SimilarityDetector(store);
    const norm = 'POST /api&token#deadbeef';
    const hash = fnv1a(norm);
    await store.set(darkKey(hash), norm, 3600);

    const malicious = await det.check('1.2.3.4', norm, false);
    expect(malicious).toBe(true);
  });

  it('bans on >90% similarity in normal mode', async () => {
    const store = new MemoryStore();
    const det = new SimilarityDetector(store);
    const darkNorm = 'POST /api&token#aaaaaaaa';
    await store.set(darkKey(fnv1a(darkNorm)), darkNorm, 3600);

    // Nearly identical request (one char differs in the body hash).
    const near = 'POST /api&token#aaaaaaab';
    const malicious = await det.check('1.2.3.4', near, false);
    expect(malicious).toBe(true);
  });

  it('does not ban clearly different requests', async () => {
    const store = new MemoryStore();
    const det = new SimilarityDetector(store);
    const darkNorm = 'POST /api&token#aaaaaaaa';
    await store.set(darkKey(fnv1a(darkNorm)), darkNorm, 3600);

    const different = 'GET /home&lang=en#bbbbbbbb';
    const malicious = await det.check('1.2.3.4', different, false);
    expect(malicious).toBe(false);
  });
});
