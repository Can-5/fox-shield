/**
 * fox-shield edge worker — Web Application Firewall.
 *
 * A set of regex signatures covering SQLi, XSS, RCE, path traversal, Log4j and
 * other OWASP CRS-lite patterns. On a match the request is dark-listed (by
 * hash), the client IP is banned, and a 403 "Blocked by WAF" is returned.
 *
 * The signature set mirrors internal/waf/waf.go (DefaultRules).
 */

import type { Store } from './store';
import { addDark, recordOffense, storeRawIp } from './store';
import { vaultEncrypt } from './hash';

export interface WafRule {
  id: string;
  category: string;
  regex: string;
}

export const DEFAULT_WAF_RULES: WafRule[] = [
  // SQL Injection
  { id: 'SQLI-001', category: 'sqli', regex: '(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|drop\\s+table|delete\\s+from|update\\s+.*\\s+set)' },
  { id: 'SQLI-002', category: 'sqli', regex: '(?i)([\'"])\\s*(or|and)\\s*([\'"])\\s*=\\s*([\'"])' },
  { id: 'SQLI-003', category: 'sqli', regex: '(?i)(--\\s|#|/\\*.*\\*/)' },
  { id: 'SQLI-004', category: 'sqli', regex: '(?i)(sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay|pg_sleep)' },
  { id: 'SQLI-005', category: 'sqli', regex: '(?i)(information_schema|sys\\.tables|mysql\\.user|sqlite_master)' },
  { id: 'SQLI-006', category: 'sqli', regex: '(?i)(0x[0-9a-f]{8,}|char\\s*\\(\\s*\\d+\\s*\\)|concat\\s*\\()' },
  { id: 'SQLI-007', category: 'sqli', regex: '(?i)(\\sor\\s+[0-9]+\\s*=\\s*[0-9]+)' },
  // XSS
  { id: 'XSS-001', category: 'xss', regex: '(?i)(<script|</script|javascript:|onerror\\s*=|onload\\s*=|onclick\\s*=)' },
  { id: 'XSS-002', category: 'xss', regex: '(?i)(<img[^>]*src|document\\.cookie|alert\\s*\\()' },
  { id: 'XSS-003', category: 'xss', regex: '(?i)(<iframe|<object|<embed|<svg[^>]*on)' },
  { id: 'XSS-004', category: 'xss', regex: '(?i)(&#x[0-9a-f]{2,};|&#\\d{2,};|%3c|%3e)' },
  // Remote Code Execution
  { id: 'RCE-001', category: 'rce', regex: '(?i)(system\\s*\\(|exec\\s*\\(|passthru\\s*\\(|shell_exec\\s*\\(|popen\\s*\\()' },
  { id: 'RCE-002', category: 'rce', regex: '(?i)(\\$\\{IFS\\}|/bin/(sh|bash)|cmd\\.exe|powershell\\s+-)' },
  { id: 'RCE-003', category: 'rce', regex: '(?i)(\\|\\s*(cat|nc|wget|curl|python|perl|php)\\b|;\\s*(cat|nc|wget|curl)\\b)' },
  { id: 'RCE-004', category: 'rce', regex: '(?i)(base64_decode\\s*\\(|eval\\s*\\(\\s*\\$|assert\\s*\\(\\s*\\$)' },
  { id: 'RCE-005', category: 'rce', regex: '(?i)(\\$\\{jndi:|log4shell|log4j)' },
  // Path Traversal
  { id: 'TRAV-001', category: 'traversal', regex: '(\\.\\./|\\.\\.\\\\|%2e%2e|%252e)' },
  { id: 'TRAV-002', category: 'traversal', regex: '(?i)(/etc/passwd|/etc/shadow|/proc/self|/windows/win\\.ini|/boot\\.ini)' },
  { id: 'TRAV-003', category: 'traversal', regex: '(?i)(file://|php://|data://|expect://|gopher://)' },
  // Other / OWASP CRS-lite
  { id: 'GEN-001', category: 'generic', regex: '(?i)(<%|%>|<\\?php|<\\?xml)' },
  { id: 'GEN-002', category: 'generic', regex: '(?i)(\\x00|%00|\\\\x00)' },
  { id: 'GEN-003', category: 'generic', regex: '(?i)(\\.env|\\.git/config|\\.aws/credentials|id_rsa)' },
  { id: 'GEN-004', category: 'generic', regex: '(?i)(\\badmin\\b.*\\bpassword\\b|root\\s*:\\s*\\*|passwd\\s*=\\s*)' },
];

export interface WafMatch {
  id: string;
  category: string;
  /** True when the request body exceeded the scan cap and could not be fully inspected. */
  oversizedBody: boolean;
}

// maxBodyBytes caps how much of the request body is scanned. Bodies larger
// than this cannot be fully inspected and are treated as suspicious rather
// than silently truncated (which would let a payload hide past the cap).
const maxBodyBytes = 1 << 20; // 1 MiB

// hopByHopHeaders are excluded from header scanning per RFC 7230 §6.1.
const hopByHopHeaders = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/** Joins relevant request headers (lowercased name:value) into a scan string. */
function headerHaystack(headers: Headers): string {
  const parts: string[] = [];
  headers.forEach((value, name) => {
    const lower = name.toLowerCase();
    if (hopByHopHeaders.has(lower)) {
      return;
    }
    parts.push(`${lower}:${value}`);
  });
  return parts.join('\n');
}

export class Waf {
  private readonly rules: WafRule[];
  private readonly store: Store;

  constructor(store: Store, rules: WafRule[] = DEFAULT_WAF_RULES) {
    this.store = store;
    this.rules = rules;
  }

  /**
   * Scans the request target, headers and body for any signature. Returns the
   * first matching rule, or a result with empty id/category when the body was
   * oversized (treated as suspicious), or null when clean.
   */
  match(
    method: string,
    pathname: string,
    search: string,
    body: string,
    headers?: Headers,
    oversizedBody = false,
  ): WafMatch | null {
    const target = `${method} ${pathname}${search}`;
    const headerStr = headers ? headerHaystack(headers) : '';
    const haystack = `${target}\n${headerStr}\n${body}`;
    for (const rule of this.rules) {
      try {
        // Go/PCRE inline (?i) flag is not valid in JS; translate to the `i` flag.
        let pattern = rule.regex;
        let flags = '';
        if (pattern.startsWith('(?i)')) {
          pattern = pattern.slice(4);
          flags = 'i';
        }
        if (new RegExp(pattern, flags).test(haystack)) {
          return { id: rule.id, category: rule.category, oversizedBody };
        }
      } catch {
        // A malformed rule must never crash the worker; skip it.
        continue;
      }
    }
    if (oversizedBody) {
      return { id: '', category: 'oversized-body', oversizedBody: true };
    }
    return null;
  }

  /**
   * Records a WAF hit: dark-lists the request hash and escalates the offense
   * ladder (see store.recordOffense). The raw IP is never used as a key — only
   * the hashed IP, device hash and subnet hash are. The raw IP is stored
   * encrypted in the vault for admin recovery.
   */
  async block(
    ipHash: string,
    deviceHash: string,
    subnetHash: string | null,
    rawIp: string,
    salt: string,
    hash: string,
    normalized: string,
    match: WafMatch,
    aggressive: boolean,
  ): Promise<void> {
    await addDark(this.store, hash, normalized, 60 * 60);
    const reason = match.id ? `waf:${match.id}:${match.category}` : 'waf:oversized-body';
    await recordOffense(this.store, ipHash, deviceHash, subnetHash, reason, aggressive);
    await storeRawIp(this.store, ipHash, rawIp, salt, vaultEncrypt);
  }
}
