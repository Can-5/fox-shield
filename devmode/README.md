# fox-shield Developer Mode

PC'ye kurulan **özel** dark-list görüntüleyici. Yalnızca sahibine özeldir — `localhost:8788` üzerinde çalışır, GitHub'da public değildir.

## Ne yapar?

- **Dark List görüntüleme:** `dark:{hash}` + `ban:{ip}` kayıtlarını gösterir (hash, IP, reason, zaman, istek örneği, ban durumu)
- **Arama / filtre:** IP, hash veya reason ile filtrele
- **Aksiyonlar:** IP unban, dark kayıt sil, hash kopyala, benzerlik eşiği ayarla, aggressive mod toggle
- **Destroyed sayacı:** Destroy fallback'i tarafından yok edilen istek sayısı
- **Canlı takip:** 1 saniyede bir yeni ban/stats poll
- **Destroy garantisi:** "Bu istek banlanamadı ama DESTROY katmanında yok edildi" durumunu net gösterir

## Kurulum (PC)

```bash
cd devmode
bun install
```

`.env` dosyası oluştur ve token'ını belirle:

```bash
cp .env.example .env
# .env içinde DEV_TOKEN=... değerini değiştir
```

## Çalıştır

```bash
bun run dev
```

→ http://localhost:8788

İlk açılışta `DEV_TOKEN` sorulur, tarayıcıda saklanır. Yanlış token → 401.

## Build (statik)

```bash
bun run build
```

Çıktı `devmode/dist/` içine gelir. Sunucu build'i `bun run start` ile servis eder.

## Backend

`server.ts` — Hono tabanlı, `:8788` portunda. `/api/dark`, `/api/stats`, `/api/unban`, `/api/mode`, `/api/threshold` uçlarını sunar.

- `REDIS_URL` tanımlıysa gerçek Redis'e (LXC origin) bağlanır
- Tanımlı değilse **mock veri** (10 örnek dark kayıt) ile demo çalışır
- Auth: `Authorization: Bearer <DEV_TOKEN>` veya `?token=<DEV_TOKEN>`
- CORS kapalı — yalnızca localhost

## KV şeması

```
ban:{ip}      -> reason
dark:{hash}   -> normalize edilmiş istek
destroy:{ip}  -> yok edilen istek sayacı
stats         -> JSON stats
```
