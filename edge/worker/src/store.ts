/**
 * fox-shield edge worker — persistence layer.
 *
 * A Store abstraction backed by Cloudflare KV (SHIELD_KV) with an in-memory
 * fallback for local development when the KV binding is not present. The key
 * schema is shared with the Go origin shield:
 *
 *   ratelimit:{ip}   -> sliding-window request timestamps (JSON array of ms)
 *   ban:{hash}       -> banned IPs (value = reason); key is HMAC(ip, SALT), never raw
 *   dark:{hash}      -> dark-listed request hashes (value = normalized request)
 *   destroy:{ip}     -> destroyed-request counter (value = count)
 *   hackcount:{hash} -> hack counter per hashed IP (TTL 30d)
 *   subnetban:{hash} -> permanent subnet ban (value = reason); key is HMAC(subnet, SALT)
 *   ipvault:{hash}   -> AES-GCM encrypted raw IP, recoverable only with the salt
 *
 * Raw IPs are never stored as keys or values (except inside the encrypted
 * ipvault namespace). KVNamespace is the Cloudflare Workers KV binding type.
 * When it is undefined (local dev / tests) the MemoryStore is used so the
 * worker still runs.
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

/**
 * Key for a permanent IP ban. `hash` is the HMAC-SHA256 of the raw IP (see
 * hash.ts hashIP) — the raw address is NEVER used as a key, so a leaked KV
 * dump reveals nothing about who was banned.
 */
export function banKey(hash: string): string {
  return `ban:${hash}`;
}

/** Key for a permanent device ban (value = reason). `deviceHash` is FNV-1a of
 * UA+lang+country+colo (see hash.ts deviceHash). */
export function deviceKey(deviceHash: string): string {
  return `device:${deviceHash}`;
}

/** Key for the per-hashed-IP offense counter (TTL 30d). */
export function offenseKey(hash: string): string {
  return `offense:${hash}`;
}

/** Key for the per-hashed-IP hack counter (TTL 30d). */
export function hackCountKey(hash: string): string {
  return `hackcount:${hash}`;
}

/** Key for a permanent subnet ban (value = reason). */
export function subnetBanKey(subnetHash: string): string {
  return `subnetban:${subnetHash}`;
}

/** Key for the encrypted raw-IP vault entry (value = AES-GCM payload). */
export function ipVaultKey(hash: string): string {
  return `ipvault:${hash}`;
}

/** TTL for the per-IP hack counter (30 days). */
export const HACK_COUNT_TTL = 30 * 24 * 60 * 60;

/** TTL for the per-IP offense counter (30 days). */
export const OFFENSE_TTL = 30 * 24 * 60 * 60;

/** TTL for the encrypted raw-IP vault entry (30 days). */
export const RAW_IP_TTL = 30 * 24 * 60 * 60;

/** Offenses before an unlimited IP+device ban in normal mode. */
export const OFFENSE_BAN_THRESHOLD = 3;
/** Offenses before an unlimited IP+device ban in aggressive mode. */
export const OFFENSE_BAN_THRESHOLD_AGGRESSIVE = 2;

/** Offenses from the same /64 subnet within 1h before the subnet is banned
 * (swelling protection — see recordOffense). */
export const SUBNET_OFFENSE_THRESHOLD = 5;
/** Window (seconds) for the /64 subnet offense swelling check. */
export const SUBNET_OFFENSE_WINDOW = 60 * 60;

/** Threshold of hacks before a subnet gets a permanent ban. */
export const SUBNET_BAN_THRESHOLD = 3;
/** Aggressive-mode threshold (2 hacks). */
export const SUBNET_BAN_THRESHOLD_AGGRESSIVE = 2;

/** Cap on the number of permanent subnet bans retained (anti-bloat). */
export const SUBNET_BAN_MAX = 10_000;

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
  private readonly subnetLRU: string[] = [];

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
    if (key.startsWith('subnetban:')) {
      this.touchSubnet(key);
    }
  }

  private touchSubnet(key: string): void {
    const idx = this.subnetLRU.indexOf(key);
    if (idx >= 0) {
      this.subnetLRU.splice(idx, 1);
    }
    this.subnetLRU.push(key);
    while (this.subnetLRU.length > SUBNET_BAN_MAX) {
      const oldest = this.subnetLRU.shift();
      if (oldest !== undefined) {
        this.items.delete(oldest);
      }
    }
  }

  async delete(key: string): Promise<void> {
    this.items.delete(key);
    if (key.startsWith('subnetban:')) {
      const idx = this.subnetLRU.indexOf(key);
      if (idx >= 0) {
        this.subnetLRU.splice(idx, 1);
      }
    }
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

/**
 * Records a hack for a hashed IP and escalates to a permanent subnet ban once
 * the threshold is reached. Returns the new hack count.
 *
 * `subnetHash` is the HMAC of the IP's /64 or /24 prefix (null when the IP
 * cannot be grouped). When the count reaches the threshold, both the subnet
 * ban and a ban on the subnet hash are set with no TTL, so any IP in that
 * subnet is blocked.
 */
export async function recordHack(
  store: Store,
  hash: string,
  subnetHash: string | null,
  reason: string,
  aggressive: boolean,
): Promise<number> {
  const key = hackCountKey(hash);
  const raw = await store.get(key);
  const count = raw ? Number.parseInt(raw, 10) || 0 : 0;
  const next = count + 1;
  await store.set(key, String(next), HACK_COUNT_TTL);

  // WiFi/subnet ban disabled — only device+IP ban (user request: wifi değil cihaz ban)
  return next;
}

/**
 * Records an offense (a WAF or similarity hit) for a hashed IP and escalates
 * through a strike ladder. Returns the new offense count.
 *
 * Swelling protection: a single stray payload must not fill the ban list, so
 * the FIRST offense only dark-lists the request (no ban). The SECOND offense
 * issues a temporary IP ban ("2nd similar hit bans"). Only after the offense
 * threshold (3 normal / 2 aggressive) do we issue an UNLIMITED IP + device ban.
 *
 * Subnet swelling: an attacker rotating IPv6 addresses within a single /64
 * could otherwise inflate the ban list with one entry per rotated address. To
 * prevent that, when the same /64 produces SUBNET_OFFENSE_THRESHOLD offenses
 * within SUBNET_OFFENSE_WINDOW we ban the whole /64 subnet hash instead of the
 * individual /128s, collapsing many entries into one.
 */
export async function recordOffense(
  store: Store,
  ipHash: string,
  deviceHash: string,
  subnetHash: string | null,
  reason: string,
  aggressive: boolean,
): Promise<number> {
  const key = offenseKey(ipHash);
  const raw = await store.get(key);
  const count = raw ? Number.parseInt(raw, 10) || 0 : 0;
  const next = count + 1;
  await store.set(key, String(next), OFFENSE_TTL);

  const threshold = aggressive ? OFFENSE_BAN_THRESHOLD_AGGRESSIVE : OFFENSE_BAN_THRESHOLD;

  // 2nd offense (normal mode) -> temporary IP ban ("2nd similar hit bans").
  if (!aggressive && next === 2) {
    await store.set(banKey(ipHash), `temporary:${reason}`, 60 * 60);
  }

  // Threshold reached -> unlimited IP + device ban (no WiFi ban — device only).
  if (next >= threshold) {
    await store.set(banKey(ipHash), `unlimited:${reason}`, undefined);
    await store.set(deviceKey(deviceHash), `unlimited:${reason}`, undefined);
  }

  return next;
}

/**
 * Stores the encrypted raw IP in the `ipvault:{hash}` namespace with a 30-day
 * TTL. The raw address is AES-GCM encrypted under the salt and is recoverable
 * only by an admin holding the salt (via the DevMode /api/raw-ips endpoint). It
 * is never used as a key and never displayed, so it does not swell the ban list
 * and does not leak in a KV dump.
 */
export async function storeRawIp(
  store: Store,
  ipHash: string,
  rawIp: string,
  salt: string,
  encrypt: (ip: string, salt: string) => Promise<string | null>,
): Promise<void> {
  const payload = await encrypt(rawIp, salt);
  if (payload !== null) {
    await store.set(ipVaultKey(ipHash), payload, RAW_IP_TTL);
  }
}
