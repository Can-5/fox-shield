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
      await this.kv.put(key, value, { expirationTtl: ttlSeconds });
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
