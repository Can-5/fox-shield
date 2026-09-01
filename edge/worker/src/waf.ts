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
import { darkKey, banKey } from './store';

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
}

export class Waf {
  private readonly rules: WafRule[];
  private readonly store: Store;

  constructor(store: Store, rules: WafRule[] = DEFAULT_WAF_RULES) {
    this.store = store;
    this.rules = rules;
  }

  /**
   * Scans the request target and body for any signature. Returns the first
   * matching rule, or null when clean.
   */
  match(method: string, pathname: string, search: string, body: string): WafMatch | null {
    const target = `${method} ${pathname}${search}`;
    const haystack = `${target}\n${body}`;
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
          return { id: rule.id, category: rule.category };
        }
      } catch {
        // A malformed rule must never crash the worker; skip it.
        continue;
      }
    }
    return null;
  }

  /**
   * Records a WAF hit: dark-lists the request hash and bans the IP. Returns the
   * match so the caller can log it.
   */
  async block(ip: string, hash: string, normalized: string, match: WafMatch): Promise<void> {
    await this.store.set(darkKey(hash), normalized, 60 * 60);
    await this.store.set(banKey(ip), `waf:${match.id}:${match.category}`, 60 * 60);
  }
}
