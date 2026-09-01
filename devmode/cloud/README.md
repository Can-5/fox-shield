# fox-shield Developer Mode — Özel Bulut Dağıtımı

DevMode'u kendi PC'ne ek olarak **özel** bir bulut örneğine de kurabilirsin.
Her iki mod da **DEV_TOKEN** ile korunur — başkası erişirse 401 alır.

> ⚠️ Önemli: Bulut örneği yalnızca **senin token'ınla** erişilebilir. Public değildir.
> `DEV_TOKEN`'ı asla public bir yere (README, GitHub public repo, log) koyma.

---

## Seçenek A — Cloudflare Workers (önerilen)

`https://fox-shield-dev.workers.dev` adresinde çalışır.

### 1. KV namespace oluştur

```bash
wrangler kv namespace create SHIELD_KV
```

Çıktıdaki `id` değerini `devmode/wrangler.toml` içindeki
`REPLACE_WITH_KV_NAMESPACE_ID` yerine yapıştır.

### 2. Token'ı secret olarak set et

```bash
cd devmode
wrangler secret put DEV_TOKEN
# istendiğinde token'ını gir
```

### 3. Deploy

```bash
wrangler deploy
```

→ `https://fox-shield-dev.workers.dev`

Tarayıcıda aç, `DEV_TOKEN` gir. Başkası açarsa **401** alır.

### Güncelleme

```bash
wrangler deploy
```

---

## Seçenek B — GitHub Pages (statik)

Sunucu olmadan, yalnızca statik admin paneli. Yine token sorar (client-side).

### 1. Build

```bash
cd devmode
bun run build
```

Çıktı `devmode/dist/` içine gelir.

### 2. Pages'e yükle

- GitHub repo'da **Settings → Pages → Deploy from a branch**
- `dist/` klasörünü (veya build çıktısını) `gh-pages` branch'ine koy
- VEYA GitHub Actions ile otomatik deploy

> Not: Statik modda `/api/*` uçları çalışmaz (sunucu yok). Sadece görüntüleme
> ve client-side token doğrulaması yapılır. Tam yönetim için Seçenek A'yı kullan.

---

## Güvenlik Notları

- **Device binding:** Yerel modda yalnızca senin PC'n erişir (`.device_id`).
  Bulut modda `ALLOW_REMOTE=true` olduğu için herkese açık değil — yine de
  `DEV_TOKEN` zorunludur.
- **Token:** `wrangler secret` ile saklanır, asla `wrangler.toml` içine yazma.
- **CORS:** Yalnızca localhost + `ALLOWED_ORIGINS` içindeki origin'ler kabul edilir.
