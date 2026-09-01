/**
 * Minimal type declarations for the `bun` module surface used by server.ts.
 * (Full @types/bun is not required for this small surface.)
 */

declare module 'bun' {
  export interface BunServeOptions {
    port?: number | string;
    hostname?: string;
    fetch(request: Request): Response | Promise<Response>;
    error?(error: Error): Response | Promise<Response>;
  }

  export function serve(options: BunServeOptions): unknown;
}
