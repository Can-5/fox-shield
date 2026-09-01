# fox-shield edge worker

Cloudflare Workers implementation of the fox-shield v1.0 shield. Runs the same
middleware chain as the Go origin shield on Cloudflare's 300 PoP network at
zero cost.

## Middleware chain

```
limiter -> waf -> similarity -> challenge -> destroy -> origin fetch
```

| Layer | Behavior |
|-------|----------|
| **limiter** | Sliding window per IP. Normal 20 rps / burst 40; aggressive 10 rps / burst 20. Returns `429` with `Retry-After`; bans after repeated violations or an immediate burst breach. |
| **waf** | 20+ regex signatures (SQLi, XSS, RCE, path traversal, Log4j). On match: dark-lists the request hash, bans the IP, returns `403 Blocked by WAF`. |
| **similarity** | Normalizes request (method + path + sorted query keys + body hash), FNV-1a hash, Levenshtein similarity against the dark list. Bans above 0.90 (normal) / 0.85 (aggressive). |
| **challenge** | `/__shield/challenge` serves a JS proof-of-work page (SHA-256, difficulty 4 normal / 5 aggressive). On success sets `__shield_pass` cookie (10m). Failed proof falls back to a CAPTCHA placeholder. |
| **destroy** | Final drop layer. If a request was flagged malicious but not banned (race condition), returns `403 Destroyed` and never reaches the origin. |
| **origin** | Forwards clean requests to `ORIGIN_URL` with Cloudflare headers stripped. |

## KV keys

```
ratelimit:{ip}   sliding-window request timestamps (JSON array of ms)
ban:{ip}         banned IPs (value = reason)
dark:{hash}      dark-listed request hashes (value = normalized request)
destroy:{ip}     destroyed-request counter
```

## Local development

```bash
bun install
bun run dev        # wrangler dev (in-memory store fallback if KV not bound)
bun run test       # vitest
bun run typecheck  # tsc --noEmit
```

## Deploy

1. Create a KV namespace and put its ID in `wrangler.toml`:

   ```bash
   wrangler kv namespace create SHIELD_KV
   ```

   Copy the returned `id` into `wrangler.toml` under `[[kv_namespaces]]`.

2. Set the origin URL (and aggressive mode if desired) in `wrangler.toml`
   `[vars]`, or via secrets:

   ```bash
   wrangler secret put ORIGIN_URL
   ```

3. Deploy:

   ```bash
   bun run deploy    # wrangler deploy
   ```

## Environment variables

| Var | Default | Description |
|-----|---------|-------------|
| `AGGRESSIVE_MODE` | `false` | `true` tightens limits (10 rps), thresholds (0.85) and challenge difficulty (5). |
| `ORIGIN_URL` | `http://127.0.0.1:3000` | Upstream origin base URL. |
| `SHIELD_KV` | — | KV namespace binding (optional; in-memory fallback in dev). |
