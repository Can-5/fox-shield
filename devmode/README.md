# fox-shield Developer Mode

PC'ye kurulan **özel** dark-list görüntüleyici + **tam yönetim paneli**.
Yalnızca sahibine özeldir — `localhost:8788` üzerinde çalışır, GitHub'da public değildir.

## Ne yapar?

- **Dark List görüntüleme:** `dark:{hash}` + `ban:{ip}` kayıtlarını gösterir (hash, IP, reason, zaman, istek örneği, ban durumu)
- **Arama / filtre:** IP, hash veya reason ile filtrele
- **Aksiyonlar:** IP unban, dark kayıt sil, hash kopyala, benzerlik eşiği ayarla, aggressive mod toggle
- **Destroyed sayacı:** Destroy fallback'i tarafından yok edilen istek sayısı
- **Canlı takip:** 1 saniyede bir yeni ban/stats poll
- **Destroy garantisi:** "Bu istek banlanamadı ama DESTROY katmanında yok edildi" durumunu net gösterir
- **🔒 Cihaz bağlama:** DevMode yalnızca senin PC'ne özel — başka cihazdan erişim engellenir
- **⚙️ Tam yönetim paneli:** Tüm ayarlar düzenlenebilir (limitler, challenge, benzerlik, kota, güvenlik, geo, whitelist, manuel ban, danger zone)

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

## Çalıştır (Yerel mod — sadece bu PC)

```bash
bun run dev
```

→ http://localhost:8788

İlk açılışta `DEV_TOKEN` sorulur, tarayıcıda saklanır. Yanlış token → 401.
Cihaz bağlama aktif: yalnızca bu PC erişir, başkası → 403.

## Build (statik)

```bash
bun run build
```

Çıktı `devmode/dist/` içine gelir. Sunucu build'i `bun run start` ile servis eder.

## Özel Bulut Dağıtımı (opsiyonel)

DevMode'u kendi PC'ne ek olarak özel bir bulut örneğine de kurabilirsin —
yine token korumalı:

- **Cloudflare Workers:** `wrangler deploy` → `https://fox-shield-dev.workers.dev` → sadece DEV_TOKEN ile erişilir, başkası 401
- **GitHub Pages:** `bun run build` → `dist/` → Pages'e deploy → yine token sorar

Detaylı adımlar: [`devmode/cloud/README.md`](cloud/README.md)

## Backend

`server.ts` — Hono tabanlı, `127.0.0.1:8788` portunda.

### API uçları (hepsi DEV_TOKEN ister)

| Uç | Açıklama |
|----|----------|
| `GET /api/settings` | rules.toml + canlı ayarlar |
| `POST /api/settings` | Herhangi bir ayarı güncelle (rules.toml'a yazar, hot-reload) |
| `POST /api/ban` | IP'yi manuel banla `{ip, reason}` |
| `POST /api/unban` | IP'yi unbanyla |
| `POST /api/whitelist` | IP'yi whitelist'e ekle/çıkar `{ip, action}` |
| `POST /api/geo` | Engellenen ülkeleri güncelle `{countries}` |
| `GET /api/dark` | Tam dark list + istek örnekleri |
| `POST /api/dark/delete` | Dark kayıt sil |
| `GET /api/system` | deviceId, uptime, bellek, günlük blok, kalan kota |
| `POST /api/deploy` | Rebuild/deploy talimatları |
| `POST /api/clear-bans` | Tüm banları temizle |
| `POST /api/reset-rules` | Kuralları varsayılana döndür |
| `POST /api/factory-reset` | Fabrika sıfırlama |

### Güvenlik

- **Device binding:** İlk çalıştırmada `devmode/.device_id` üretilir (hostname + user + token hash'i). İstekler `X-Device-Id` header'ı veya localhost origin'i taşımalıdır. Başka cihaz → 403, loglanır.
- **Localhost-only:** Varsayılan `127.0.0.1:8788`'e bağlanır, localhost olmayan Host/Origin reddedilir. Cloud deploy için `ALLOW_REMOTE=true`.
- **Token:** Timing-safe hash karşılaştırması, asla düz metin loglanmaz.
- **CORS:** Yalnızca localhost + `ALLOWED_ORIGINS` kabul edilir.

### rules.toml

`server.ts` `rules.toml`'u dinamik okur/yazar (yerel modda fs, cloud modda KV).
Tüm ayar değişiklikleri rules.toml'a yazılır ve hot-reload edilir.

- `REDIS_URL` tanımlıysa gerçek Redis'e (LXC origin) bağlanır
- Tanımlı değilse **mock veri** (10 örnek dark kayıt) ile demo çalışır
- Auth: `Authorization: Bearer <DEV_TOKEN>` veya `?token=<DEV_TOKEN>`

## KV şeması

```
ban:{ip}      -> reason
dark:{hash}   -> normalize edilmiş istek
destroy:{ip}  -> yok edilen istek sayacı
stats         -> JSON stats
rules         -> rules.toml içeriği (cloud KV mirror)
```
