/**
 * fox-shield edge worker — destroy fallback.
 *
 * The final layer in the shield chain. If a request was flagged as malicious by
 * the WAF or similarity detector but was not banned (e.g. a race condition in
 * KV), destroy drops it with a 403 "Destroyed" response and never forwards it
 * to the origin. This guarantees malicious traffic cannot reach the origin even
 * if an earlier ban failed.
 *
 * Mirrors internal/destroy/destroy.go.
 */

import type { Store } from './store';
import { destroyKey } from './store';

export class Destroyer {
  private readonly store: Store;

  constructor(store: Store) {
    this.store = store;
  }

  /**
   * Drops a flagged request: increments the per-IP destroy counter and returns
   * a 403 "Destroyed" response. Returns null when the request is not flagged
   * and should continue to the origin.
   */
  async destroy(ip: string, flagged: boolean): Promise<Response | null> {
    if (!flagged) {
      return null;
    }
    const key = destroyKey(ip);
    const raw = await this.store.get(key);
    const count = raw ? Number.parseInt(raw, 10) || 0 : 0;
    await this.store.set(key, String(count + 1), 60 * 60);
    return new Response('Destroyed', {
      status: 403,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }
}
