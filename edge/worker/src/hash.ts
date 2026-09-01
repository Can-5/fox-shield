/**
 * fox-shield edge worker — privacy-preserving IP hashing.
 *
 * Raw client IPs are NEVER stored in KV or logs. Instead we derive:
 *
 *   - hashIP(ip)      -> HMAC-SHA256(ip, SALT) hex. Used as the ban / hack-count
 *                        key so an attacker rotating IPs cannot be correlated
 *                        back to a raw address, and a leaked KV dump reveals
 *                        nothing about who was banned.
 *   - subnetHash(ip)  -> HMAC-SHA256(subnet, SALT) hex, where subnet is the
 *                        IPv6 /64 or IPv4 /24 prefix. Used for the permanent
 *                        WiFi / subnet ban: after N hacks from a subnet the
 *                        whole /64 or /24 is blocked.
 *   - maskIp(ip)      -> a display-only masked form (never a key): IPv6 shows
 *                        the first two groups + ****:****, IPv4 shows the first
 *                        two octets + .*.*.
 *   - vaultEncrypt / vaultDecrypt -> AES-GCM encryption of the raw IP under the
 *                        same SALT, stored in the separate `ipvault:{hash}`
 *                        namespace. Only an admin holding the salt can decrypt;
 *                        it is never displayed and never used as a key.
 *
 * SALT comes from the HASH_SALT env var, falling back to a hardcoded default
 * ("fox-shield-2026-salt"). The salt is the secret that makes the hashes
 * non-reversible; it must be set in production and rotated carefully.
 */

/** Resolves the HMAC/AES salt from the environment, with a dev fallback. */
export function resolveSalt(envSalt?: string): string {
  const s = envSalt && envSalt.trim() !== '' ? envSalt : 'fox-shield-2026-salt';
  return s;
}

/** Derives a 32-byte AES-GCM key from the salt via SHA-256. */
async function deriveKey(salt: string): Promise<CryptoKey> {
  const data = new TextEncoder().encode(salt);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return crypto.subtle.importKey(
    'raw',
    digest,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** HMAC-SHA256 hex digest of `input` under `salt`. */
export async function hmacSha256Hex(input: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(salt),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(input));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Returns the canonical subnet prefix for an IP: IPv6 /64 (first 64 bits),
 * IPv4 /24 (first 24 bits). Returns null for unparseable input.
 */
export function subnetOf(ip: string): string | null {
  const clean = ip.includes('%') ? ip.slice(0, ip.indexOf('%')) : ip;
  // IPv4 (dotted quad).
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) {
    const parts = clean.split('.');
    if (parts.length !== 4) {
      return null;
    }
    for (const p of parts) {
      const n = Number(p);
      if (!Number.isInteger(n) || n < 0 || n > 255) {
        return null;
      }
    }
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  // IPv6 — normalize via the browser's parser if available, else best-effort.
  if (clean.includes(':')) {
    const normalized = normalizeIpv6(clean);
    if (normalized === null) {
      return null;
    }
    // /64 = first 4 hextets.
    const groups = normalized.split(':');
    return `${groups.slice(0, 4).join(':')}::/64`;
  }
  return null;
}

/**
 * Best-effort IPv6 canonicalization: expands "::" and lowercases. Returns null
 * when the address cannot be parsed. This mirrors Go's net.ParseIP behavior
 * closely enough for /64 grouping.
 */
export function normalizeIpv6(addr: string): string | null {
  const a = addr.toLowerCase();
  if (a.includes('::')) {
    const parts = a.split('::');
    const left = parts[0] ?? '';
    const right = parts[1] ?? '';
    const leftGroups = left === '' ? [] : left.split(':');
    const rightGroups = right === '' ? [] : right.split(':');
    const missing = 8 - leftGroups.length - rightGroups.length;
    if (missing < 1) {
      return null;
    }
    const zeros = new Array<string>(missing).fill('0');
    const all = [...leftGroups, ...zeros, ...rightGroups];
    if (all.length !== 8) {
      return null;
    }
    return all.join(':');
  }
  const groups = a.split(':');
  if (groups.length !== 8) {
    return null;
  }
  return a;
}

/** HMAC-SHA256 hash of the raw IP, used as the ban / hack-count key. */
export async function hashIP(ip: string, salt: string): Promise<string> {
  return hmacSha256Hex(ip, salt);
}

/** HMAC-SHA256 hash of the IP's subnet prefix, used as the subnet-ban key. */
export async function subnetHash(ip: string, salt: string): Promise<string | null> {
  const subnet = subnetOf(ip);
  if (subnet === null) {
    return null;
  }
  return hmacSha256Hex(subnet, salt);
}

/**
 * Returns a display-only masked form of the IP. Never used as a key.
 *
 *   IPv4: 185.220.61.***   (last octet hidden)
 *   IPv6: 2a00:1d37:61::****:****:****:****  (keeps the /48 prefix, hides the
 *          remaining 5 hextets)
 *
 * The masked form is safe to show on the banned page: it reveals only the
 * coarse network prefix, never the full host address.
 */
export function maskIp(ip: string): string {
  const clean = ip.includes('%') ? ip.slice(0, ip.indexOf('%')) : ip;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) {
    const parts = clean.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
  }
  if (clean.includes(':')) {
    const normalized = normalizeIpv6(clean);
    if (normalized !== null) {
      const groups = normalized.split(':');
      // Keep the first 3 hextets (the /48 prefix), mask the remaining 5.
      return `${groups[0]}:${groups[1]}:${groups[2]}::****:****:****:****`;
    }
    // Fallback: keep the first three colon-separated tokens.
    const tokens = clean.split(':');
    return `${tokens[0]}:${tokens[1] ?? ''}:${tokens[2] ?? ''}::****:****:****:****`;
  }
  return '***.***.***.***';
}

/**
 * Computes a stable device fingerprint from the request's ambient headers.
 *
 * The fingerprint is FNV-1a (32-bit) over the concatenation of the User-Agent,
 * Accept-Language, country and colo. It is NOT a strong identifier — it groups
 * requests that share the same browser/OS/language/region, which is exactly the
 * granularity we want for a device ban: an attacker who rotates IPs but keeps
 * the same browser profile is caught, while legitimate users behind a shared
 * NAT are not over-blocked (they share an IP but not necessarily a UA+lang).
 *
 * The result is a short hex string used as the `device:{hash}` ban key. It is
 * never derived from a raw IP, so it leaks nothing about the address.
 */
export function deviceHash(
  ua: string,
  acceptLang: string,
  country: string,
  colo: string,
): string {
  const seed = `${ua}|${acceptLang}|${country}|${colo}`;
  let hash = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * Encrypts the raw IP with AES-GCM under the salt-derived key. The result is
 * stored in the `ipvault:{hash}` namespace so an admin holding the salt can
 * recover the original IP later, but it is never displayed and never used as a
 * key. Returns "iv:ct" (base64url) or null on failure.
 */
export async function vaultEncrypt(ip: string, salt: string): Promise<string | null> {
  try {
    const key = await deriveKey(salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(ip),
    );
    const ivB64 = b64url(iv);
    const ctB64 = b64url(new Uint8Array(ct));
    return `${ivB64}:${ctB64}`;
  } catch {
    return null;
  }
}

/** Decrypts a value produced by vaultEncrypt. Returns the raw IP or null. */
export async function vaultDecrypt(payload: string, salt: string): Promise<string | null> {
  try {
    const sep = payload.indexOf(':');
    if (sep <= 0) {
      return null;
    }
    const iv = unb64url(payload.slice(0, sep));
    const ct = unb64url(payload.slice(sep + 1));
    if (iv === null || ct === null) {
      return null;
    }
    const key = await deriveKey(salt);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      ct as BufferSource,
    );
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

function b64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(s: string): Uint8Array | null {
  try {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  } catch {
    return null;
  }
}
