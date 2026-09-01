# fox-shield Dashboard

Live shield dashboard for fox-shield v1.0 — Preact + Vite + TypeScript, deployed to GitHub Pages at `/fox-shield/`.

Shows **summary** telemetry only: live stats, top attacking countries, active bans, aggressive-mode switch, similarity threshold, and the 753 rps test. The private dark list is **not** shown here — it lives in [Developer Mode](../devmode) on the owner's PC.

## Features

- **Header** — fox-shield logo, live/demo status badge, Aggressive Mode switch
- **Live stats** — rps, blocked today, banned IPs, destroyed count (polls `/api/stats` every 2s, falls back to mock data)
- **Attack map** — top attacking countries as bars (mock when no API)
- **Ban list** — IP, reason, time, unban action
- **Threshold slider** — similarity 0.85–0.95
- **753 rps test** — fires a request loop or shows the k6 command
- **Dark list preview** — read-only summary, links to Developer Mode

## Development

```bash
bun install
bun run dev
```

## Build (GitHub Pages)

```bash
bun run build
```

Output goes to `dashboard/dist`. Deploy with:

```bash
bun run deploy
```

## Stack

- [Preact](https://preactjs.com/) + [Vite](https://vitejs.dev/) + TypeScript (strict)
- Apple-design polish: translucent glass, SF Pro-like type, dark mode, restrained motion, responsive
