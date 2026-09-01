/**
 * fox-shield edge worker — progressive proof-of-work challenge.
 *
 * Serves /__shield/challenge. GET returns an HTML page whose JavaScript finds a
 * nonce such that SHA-256(nonce + ip) starts with `difficulty` leading zero
 * hex characters (4 normal / 5 aggressive). The client POSTs the nonce; on
 * verification a __shield_pass cookie is set (10m expiry) and the request is
 * allowed through. If the proof is invalid the client is served a CAPTCHA
 * placeholder (a simple math challenge) as a fallback.
 *
 * Security: the pass cookie value is a random 32-byte token stored in KV with
 * a TTL, so a static or guessed cookie is rejected. The proof nonce is bound
 * to the client IP, stored server-side, and deleted after a single use to
 * prevent replay and fixation. The CAPTCHA answer is stored server-side keyed
 * by the nonce rather than embedded in the HTML.
 *
 * Mirrors internal/challenge/challenge.go.
 */

import type { Store } from './store';

export interface ChallengeConfig {
  difficultyNormal: number;
  difficultyAggressive: number;
  passTtlSeconds: number;
  nonceTtlSeconds: number;
}

export const DEFAULT_CHALLENGE_CONFIG: ChallengeConfig = {
  difficultyNormal: 4,
  difficultyAggressive: 5,
  passTtlSeconds: 10 * 60,
  nonceTtlSeconds: 2 * 60,
};

export const CHALLENGE_COOKIE = '__shield_pass';

/** Returns a random hex string of `bytes` bytes. */
export function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** SHA-256 hex digest of the input. */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Verifies that sha256(nonce + proof) starts with `difficulty` zero hex chars. */
export async function validProof(nonce: string, proof: string, difficulty: number): Promise<boolean> {
  if (nonce === '' || proof === '') {
    return false;
  }
  const hex = await sha256Hex(nonce + proof);
  return hex.startsWith('0'.repeat(difficulty));
}

/** Store key for a pass token. */
export function passKey(token: string): string {
  return `pass:${token}`;
}

/** Store key for a proof nonce (value = client IP). */
export function nonceKey(nonce: string): string {
  return `nonce:${nonce}`;
}

/** Store key for a CAPTCHA answer (value = expected answer). */
export function captchaKey(nonce: string): string {
  return `captcha:${nonce}`;
}

/** Builds the challenge HTML page with embedded proof-of-work JavaScript. */
export function challengeHtml(nonce: string, difficulty: number, ip: string): string {
  const script = `
    const nonce = ${JSON.stringify(nonce)};
    const difficulty = ${difficulty};
    const ip = ${JSON.stringify(ip)};
    async function sha256hex(s) {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
      return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    async function solve() {
      const target = '0'.repeat(difficulty);
      const status = document.getElementById('status');
      for (let proof = 0; proof < 100000000; proof++) {
        const hex = await sha256hex(nonce + proof);
        if (hex.startsWith(target)) {
          const res = await fetch('/__shield/challenge', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ nonce, proof: String(proof) }),
          });
          if (res.ok) { location.reload(); }
          else { status.textContent = 'Proof rejected — retrying.'; }
          return;
        }
        if (proof % 10000 === 0) {
          status.textContent = 'Solving proof-of-work… ' + proof;
          await new Promise(r => setTimeout(r, 0));
        }
      }
      status.textContent = 'Could not solve — please refresh.';
    }
    solve();
  `;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fox-shield — verifying you are human</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0f1115; color: #e6e8eb;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #1a1d24; border: 1px solid #2a2f3a; border-radius: 12px;
          padding: 32px; max-width: 420px; text-align: center; }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p { color: #9aa3b2; font-size: 14px; line-height: 1.5; }
  #status { color: #7fb3ff; font-size: 13px; margin-top: 16px; min-height: 18px; }
  .spinner { width: 28px; height: 28px; border: 3px solid #2a2f3a; border-top-color: #7fb3ff;
             border-radius: 50%; margin: 16px auto 0; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
  <div class="card">
    <h1>Verifying you are human</h1>
    <p>fox-shield is checking your browser with a proof-of-work challenge. This should complete in a few seconds.</p>
    <div class="spinner"></div>
    <div id="status">Starting…</div>
  </div>
  <script>${script}</script>
</body>
</html>`;
}

/** Builds the CAPTCHA placeholder page (simple math challenge). */
export function captchaHtml(nonce: string, ip: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>fox-shield — CAPTCHA</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0f1115; color: #e6e8eb;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #1a1d24; border: 1px solid #2a2f3a; border-radius: 12px; padding: 32px; max-width: 360px; }
  h1 { font-size: 20px; margin: 0 0 16px; }
  form { display: flex; flex-direction: column; gap: 12px; }
  input { padding: 10px; border-radius: 8px; border: 1px solid #2a2f3a; background: #0f1115; color: #e6e8eb; }
  button { padding: 10px; border-radius: 8px; border: 0; background: #7fb3ff; color: #0f1115; font-weight: 600; cursor: pointer; }
</style>
</head>
<body>
  <div class="card">
    <h1>Human verification</h1>
    <p>Please solve the math problem shown below.</p>
    <form method="POST" action="/__shield/challenge">
      <input type="hidden" name="nonce" value="${nonce}">
      <input type="hidden" name="ip" value="${ip}">
      <input type="number" name="answer" required autofocus placeholder="Your answer">
      <button type="submit">Verify</button>
    </form>
  </div>
</body>
</html>`;
}

export class Challenge {
  private readonly cfg: ChallengeConfig;
  private readonly store: Store;

  constructor(store: Store, cfg: ChallengeConfig = DEFAULT_CHALLENGE_CONFIG) {
    this.store = store;
    this.cfg = cfg;
  }

  private difficulty(aggressive: boolean): number {
    return aggressive ? this.cfg.difficultyAggressive : this.cfg.difficultyNormal;
  }

  /** Serves the challenge page for a GET request. */
  async serve(ip: string, aggressive: boolean): Promise<Response> {
    const nonce = randomHex(16);
    // Bind the nonce to the client IP, stored server-side with a TTL.
    await this.store.set(nonceKey(nonce), ip, this.cfg.nonceTtlSeconds);
    const html = challengeHtml(nonce, this.difficulty(aggressive), ip);
    return new Response(html, {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  /**
   * Verifies a submitted proof (JSON { nonce, proof } or CAPTCHA form data).
   * On success sets the __shield_pass cookie and returns a 200; otherwise
   * returns the CAPTCHA placeholder.
   */
  async verify(request: Request, ip: string, aggressive: boolean): Promise<Response> {
    const contentType = request.headers.get('content-type') ?? '';

    if (contentType.includes('application/json')) {
      let nonce = '';
      let proof = '';
      try {
        const body: unknown = await request.json();
        if (typeof body === 'object' && body !== null) {
          const rec = body as Record<string, unknown>;
          if (typeof rec.nonce === 'string') nonce = rec.nonce;
          if (typeof rec.proof === 'string') proof = rec.proof;
        }
      } catch {
        return new Response('Bad Request', { status: 400 });
      }
      if (await this.validProof(nonce, proof, this.difficulty(aggressive), ip)) {
        return this.passResponse(ip);
      }
      // Proof failed -> CAPTCHA placeholder fallback.
      return this.captchaResponse(ip);
    }

    // Form-encoded CAPTCHA submission.
    const form = await request.formData();
    const nonce = form.get('nonce');
    const answer = form.get('answer');
    if (typeof nonce === 'string' && typeof answer === 'string' && (await this.validCaptcha(nonce, answer, ip))) {
      return this.passResponse(ip);
    }
    return this.captchaResponse(ip);
  }

  /**
   * Validates a proof-of-work submission. The nonce must have been issued for
   * this client IP and is deleted after a single use to prevent replay.
   */
  private async validProof(nonce: string, proof: string, difficulty: number, ip: string): Promise<boolean> {
    if (nonce === '' || proof === '') {
      return false;
    }
    const boundIp = await this.store.get(nonceKey(nonce));
    // Delete the nonce immediately (one-time use) regardless of proof result.
    await this.store.delete(nonceKey(nonce));
    if (boundIp !== ip) {
      return false;
    }
    return validProof(nonce, proof, difficulty);
  }

  /**
   * Validates a CAPTCHA answer. The expected answer is stored server-side
   * keyed by the nonce and deleted after a single use.
   */
  private async validCaptcha(nonce: string, answer: string, ip: string): Promise<boolean> {
    if (nonce === '' || answer === '') {
      return false;
    }
    const boundIp = await this.store.get(nonceKey(nonce));
    const expected = await this.store.get(captchaKey(nonce));
    // Delete both keys immediately (one-time use).
    await this.store.delete(nonceKey(nonce));
    await this.store.delete(captchaKey(nonce));
    if (boundIp !== ip || expected === null) {
      return false;
    }
    return expected === answer;
  }

  /** Serves the CAPTCHA placeholder, storing the answer server-side. */
  private async captchaResponse(ip: string): Promise<Response> {
    const nonce = randomHex(16);
    const a = Math.floor(Math.random() * 9) + 1;
    const b = Math.floor(Math.random() * 9) + 1;
    const answer = String(a + b);
    await this.store.set(nonceKey(nonce), ip, this.cfg.nonceTtlSeconds);
    await this.store.set(captchaKey(nonce), answer, this.cfg.nonceTtlSeconds);
    return new Response(captchaHtml(nonce, ip), {
      status: 403,
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  /** Issues a random pass token, stores it, and sets the __shield_pass cookie. */
  private async passResponse(ip: string): Promise<Response> {
    const token = randomHex(32);
    await this.store.set(passKey(token), ip, this.cfg.passTtlSeconds);
    const cookie = `${CHALLENGE_COOKIE}=${token}; Path=/; Max-Age=${this.cfg.passTtlSeconds}; HttpOnly; SameSite=Lax`;
    return new Response('ok', {
      status: 200,
      headers: { 'set-cookie': cookie, 'cache-control': 'no-store' },
    });
  }

  /** Reports whether the request carries a valid, issued pass cookie. */
  async hasValidPass(request: Request, ip: string): Promise<boolean> {
    const cookieHeader = request.headers.get('cookie');
    if (!cookieHeader) {
      return false;
    }
    const token = extractCookie(cookieHeader, CHALLENGE_COOKIE);
    if (!token) {
      return false;
    }
    const boundIp = await this.store.get(passKey(token));
    return boundIp === ip;
  }
}

/** Extracts a cookie value by name from a Cookie header. */
export function extractCookie(header: string, name: string): string | null {
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) {
      continue;
    }
    const key = part.slice(0, eq).trim();
    if (key === name) {
      return part.slice(eq + 1).trim();
    }
  }
  return null;
}
