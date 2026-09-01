/**
 * fox-shield edge worker — malicious-request similarity detector.
 *
 * Each request is normalized to a canonical string (method + pathname + sorted
 * query keys + body hash) and hashed with FNV-1a. The hash is compared against
 * the dark list; an exact hit is always malicious. Otherwise the normalized
 * request is compared against stored dark-list values using a Levenshtein-based
 * similarity score. When the score exceeds the threshold (0.90 normal / 0.85
 * aggressive) the request is banned and dark-listed.
 *
 * Mirrors internal/similarity/similarity.go.
 */

import type { Store } from './store';
import { darkKey, banKey, addDark, darkIndexValues } from './store';

export interface SimilarityConfig {
  threshold: number;
  aggressiveThreshold: number;
  banSeconds: number;
}

export const DEFAULT_SIMILARITY_CONFIG: SimilarityConfig = {
  threshold: 0.9,
  aggressiveThreshold: 0.85,
  banSeconds: 60 * 60,
};

/** FNV-1a 32-bit hash, returned as an 8-char lowercase hex string. */
export function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  // Force unsigned 32-bit.
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/** Normalizes a request into a canonical string for hashing/comparison. */
export function normalizeRequest(
  method: string,
  pathname: string,
  query: URLSearchParams,
  body: string,
): string {
  const keys: string[] = [];
  query.forEach((_value, key) => {
    keys.push(key);
  });
  keys.sort();
  const queryPart = keys.map((k) => `&${k}`).join('');
  const bodyHash = fnv1a(body);
  return `${method} ${pathname}${queryPart}#${bodyHash}`;
}

/** Levenshtein edit distance between two strings. */
export function levenshtein(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;
  if (la === 0) {
    return lb;
  }
  if (lb === 0) {
    return la;
  }
  let prev = new Array<number>(lb + 1);
  let curr = new Array<number>(lb + 1);
  for (let j = 0; j <= lb; j++) {
    prev[j] = j;
  }
  for (let i = 1; i <= la; i++) {
    curr[0] = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const del = (prev[j] ?? 0) + 1;
      const ins = (curr[j - 1] ?? 0) + 1;
      const sub = (prev[j - 1] ?? 0) + cost;
      curr[j] = Math.min(del, ins, sub);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[lb] ?? 0;
}

/** Normalized Levenshtein-based similarity in [0, 1]. */
export function similarity(a: string, b: string): number {
  if (a === b) {
    return 1;
  }
  if (a.length === 0 || b.length === 0) {
    return 0;
  }
  const dist = levenshtein(a, b);
  const maxLen = Math.max(a.length, b.length);
  return 1 - dist / maxLen;
}

export class SimilarityDetector {
  private readonly store: Store;
  private readonly cfg: SimilarityConfig;

  constructor(store: Store, cfg: SimilarityConfig = DEFAULT_SIMILARITY_CONFIG) {
    this.store = store;
    this.cfg = cfg;
  }

  /**
   * Evaluates a normalized request against the dark list. Returns true when the
   * request is malicious (exact dark-list hit or similarity above threshold).
   */
  async check(
    ip: string,
    normalized: string,
    aggressive: boolean,
  ): Promise<boolean> {
    const hash = fnv1a(normalized);

    // Exact dark-list hit is always malicious.
    if ((await this.store.get(darkKey(hash))) !== null) {
      await this.store.set(banKey(ip), 'similarity exact match', this.cfg.banSeconds);
      return true;
    }

    const threshold = aggressive ? this.cfg.aggressiveThreshold : this.cfg.threshold;

    // Compare against the bounded index of recent dark-list values. This works
    // with KV (which cannot be enumerated) as well as the in-memory store.
    const darkValues = await darkIndexValues(this.store);
    for (const value of darkValues) {
      if (similarity(normalized, value) >= threshold) {
        await addDark(this.store, hash, normalized, this.cfg.banSeconds);
        await this.store.set(banKey(ip), 'similarity match', this.cfg.banSeconds);
        return true;
      }
    }
    return false;
  }
}
