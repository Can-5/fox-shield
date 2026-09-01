# 🦊 fox-shield

> Cloudflare mantığını taklit eden hibrit DDoS/WAF kalkanı — 0 TL serversız başlat, LXC gelince çifte katman.

[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-distroless-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=flat-square&logo=cloudflare&logoColor=white)](wrangler.toml)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white)](docker-compose.yml)

Tek repo, iki mod: **edge** (Cloudflare Workers, 0 TL, global PoP) ve **origin** (LXC Docker Go proxy). Kurallar %100 ortak (`rules.toml`).

---

## Mimari

```
[Internet] → [Cloudflare DNS + 300 PoP] → [fox-shield Worker (edge)] → [Origin]
                                              ↓ KV (IP rep, counters, dark list)
                                              ↓
                                        [LXC Go Shield (origin)] → [Origin app]
                                              ↓ Redis (aynı şema)
                                              ↓
                                        [Developer Mode — localhost:8788] → Dark List viewer
                                        [Dashboard — GitHub Pages]
```

## Özellikler

- **Rate-limit:** Normal 20 rps / IP, Agresif 10 rps (15'e çekilebilir), burst 40/20, sliding window 1s
- **WAF:** 20+ regex imzası (SQLi, XSS, RCE, traversal) — eşleşirse direkt ban + 403
- **Benzerlik:** Normalize istek → hash → Levenshtein/Jaccard >0.90 → ban
- **Challenge:** JS proof-of-work (SHA-256, difficulty 4/5), `__shield_pass` cookie
- **Destroy:** Son middleware — kötü istek origin'e asla gitmez, `403 Destroyed`
- **753 rps testi:** Tek IP 753 rps → anında ban, 0 origin

## Hızlı Başlangıç

### Origin (Go, Docker)

```bash
# Yerel geliştirme
go run ./cmd/shield

# Docker (shield + redis)
docker compose up -d
```

Ortam değişkenleri:

| Değişken | Varsayılan | Açıklama |
|----------|-----------|----------|
| `FOX_MODE` | `origin` | Çalışma modu |
| `ORIGIN_URL` | `http://127.0.0.1:3000` | Origin uygulama adresi |
| `REDIS_URL` | *(boş → in-memory)* | Redis bağlantısı |
| `AGGRESSIVE_MODE` | `false` | Agresif mod (10 rps, zor challenge) |
| `LISTEN_ADDR` | `:8080` | Dinleme adresi |

### Edge (Cloudflare Workers)

```bash
cd edge/worker
npm install
wrangler deploy
```

### LXC Kurulumu

```bash
bash scripts/setup-lxc.sh
```

SYNPROXY + sysctl tuning. Privileged değilse güvenle atlar (userspace-only).

## Test

```bash
# 753 rps tek IP yük testi (k6)
k6 run tests/load-753.js

# veya autocannon (Node)
npx autocannon -c 50 -d 10 http://127.0.0.1:8080/
```

## Deploy

- **Serversız (şimdi):** `wrangler deploy` → Worker, `bun run deploy:pages` → Dashboard
- **LXC (sonra):** `docker compose up -d`
- **DevMode (PC):** `cd devmode && bun install && bun run dev` → localhost:8788

## Lisans

MIT
