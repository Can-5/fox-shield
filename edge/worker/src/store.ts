/**
 * fox-shield edge worker — persistence layer.
 *
 * A Store abstraction backed by Cloudflare KV (SHIELD_KV) with an in-memory
 * fallback for local development when the KV binding is not present. The key
 * schema is shared with the Go origin shield:
 *
 *   ratelimit:{ip}   -> sliding-window request timestamps (JSON array of ms)
 *   ban:{ip}         -> banned IPs (value = reason)
 *   dark:{hash}      -> dark-listed request hashes (value = normalized request)
 *   destroy:{ip}     -> destroyed-request counter (value = count)
 *
 * KVNamespace is the Cloudflare Workers KV binding type. When it is undefined
 * (local dev / tests) the MemoryStore is used so the worker still runs.
 */

/** Minimal KV surface we depend on, so tests can inject a fake. */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

/** The Cloudflare KVNamespace binding type (from @cloudflare/workers-types). */
export type KVNamespace = KVLike;

/** Store contract used by the shield middleware chain. */
export interface Store {
  /** Returns the value under key, or null when absent/expired. */
  get(key: string): Promise<string | null>;
  /** Stores value under key with an optional TTL in seconds (0 = no expiry). */
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
  /** Deletes a key. */
  delete(key: string): Promise<void>;
  /** Returns all non-expired values (used by the similarity dark-list scan). */
  snapshot(): Promise<string[]>;
}

/** Key helpers centralize the shared schema (mirrors internal/store/keys.go). */
export function rateLimitKey(ip: string): string {
  return `ratelimit:${ip}`;
}

export function banKey(ip: string): string {
  return `ban:${ip}`;
}

export function darkKey(hash: string): string {
  return `dark:${hash}`;
}

export function destroyKey(ip: string): string {
  return `destroy:${ip}`;
}

/**
 * Key under which the bounded index of recent dark-list hashes is stored.
 *
 * Cloudflare KV cannot be enumerated from the Worker runtime, so the similarity
 * detector cannot scan the whole dark list. Instead we maintain a bounded JSON
 * array of the most recent dark hashes under this single key; the similarity
 * detector reads it and fetches each hash's value via a direct KV get. This
 * keeps the Levenshtein scan working in production (KV mode) as well as in the
 * in-memory fallback.
 */
export function darkIndexKey(): string {
  return 'dark:index';
}

/** Maximum number of dark hashes retained in the index for similarity scans. */
export const DARK_INDEX_MAX = 100;

/**
 * Adds a hash to the dark list and maintains the bounded dark index. Both the
 * WAF and the similarity detector use this so every dark-listed request is
 * visible to the similarity scan regardless of the backing store.
 */
export async function addDark(
  store: Store,
  hash: string,
  value: string,
  ttlSeconds: number,
): Promise<void> {
  await store.set(darkKey(hash), value, ttlSeconds);

  const raw = await store.get(darkIndexKey());
  let index: string[] = [];
  if (raw) {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        index = parsed.filter((v): v is string => typeof v === 'string');
      }
    } catch {
      index = [];
    }
  }
  // De-duplicate (most recent wins) and keep the newest DARK_INDEX_MAX entries.
  index = index.filter((h) => h !== hash);
  index.push(hash);
  if (index.length > DARK_INDEX_MAX) {
    index = index.slice(index.length - DARK_INDEX_MAX);
  }
  await store.set(darkIndexKey(), JSON.stringify(index), ttlSeconds);
}

/**
 * Returns the values of the most recent dark-listed hashes, for the similarity
 * scan. Works with both KV and the in-memory store.
 */
export async function darkIndexValues(store: Store): Promise<string[]> {
  const raw = await store.get(darkIndexKey());
  if (!raw) {
    return [];
  }
  let index: string[] = [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      index = parsed.filter((v): v is string => typeof v === 'string');
    }
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const h of index) {
    const v = await store.get(darkKey(h));
    if (v !== null) {
      out.push(v);
    }
  }
  return out;
}

/** KV-backed Store. */
export class KVStore implements Store {
  private readonly kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async get(key: string): Promise<string | null> {
    return this.kv.get(key);
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds && ttlSeconds > 0) {
      const ttl = Math.max(60, ttlSeconds);
      await this.kv.put(key, value, { expirationTtl: ttl });
    } else {
      await this.kv.put(key, value);
    }
  }

  async delete(key: string): Promise<void> {
    await this.kv.delete(key);
  }

  async snapshot(): Promise<string[]> {
    // KV does not support enumeration from the Worker runtime. The similarity
    // detector therefore relies on the in-memory fallback for the dark-list
    // scan; with a real KV binding, exact dark-list hits still work via get().
    return [];
  }
}

interface MemItem {
  value: string;
  expiresAt: number; // epoch ms, 0 = no expiry
}

/** Thread-safe in-memory Store used when KV is not bound (local dev / tests). */
export class MemoryStore implements Store {
  private readonly items = new Map<string, MemItem>();

  private isExpired(item: MemItem, now: number): boolean {
    return item.expiresAt !== 0 && now >= item.expiresAt;
  }

  async get(key: string): Promise<string | null> {
    const item = this.items.get(key);
    if (!item) {
      return null;
    }
    if (this.isExpired(item, Date.now())) {
      this.items.delete(key);
      return null;
    }
    return item.value;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    const expiresAt = ttlSeconds && ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : 0;
    this.items.set(key, { value, expiresAt });
  }

  async delete(key: string): Promise<void> {
    this.items.delete(key);
  }

  async snapshot(): Promise<string[]> {
    const now = Date.now();
    const out: string[] = [];
    for (const item of this.items.values()) {
      if (!this.isExpired(item, now)) {
        out.push(item.value);
      }
    }
    return out;
  }
}

/** Builds the appropriate store for the given env. */
export function createStore(kv: KVNamespace | undefined): Store {
  if (kv) {
    return new KVStore(kv);
  }
  return new MemoryStore();
}
