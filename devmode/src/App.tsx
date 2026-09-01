import { useEffect, useMemo, useState } from 'preact/hooks';
import { AuthGate } from './components/AuthGate';
import { Stats } from './components/Stats';
import { DarkList } from './components/DarkList';
import {
  fetchDark,
  fetchStats,
  unban,
  deleteDark,
  setThreshold,
  setMode,
  getToken,
  clearToken,
  AuthError,
} from './api';
import type { DarkEntry, DevStats } from './types';

export function App() {
  const [authed, setAuthed] = useState(() => getToken().length > 0);
  const [entries, setEntries] = useState<DarkEntry[]>([]);
  const [stats, setStats] = useState<DevStats | null>(null);
  const [filter, setFilter] = useState('');
  const [threshold, setThresholdValue] = useState(0.9);
  const [aggressive, setAggressive] = useState(false);
  const [error, setError] = useState('');

  // Live tail — poll every 1s for new bans / stats.
  useEffect(() => {
    if (!authed) {
      return;
    }
    let cancelled = false;

    const tick = async () => {
      try {
        const [d, s] = await Promise.all([fetchDark(), fetchStats()]);
        if (cancelled) {
          return;
        }
        setEntries(d);
        setStats(s);
        setThresholdValue(s.threshold);
        setAggressive(s.aggressive);
        setError('');
      } catch (err) {
        if (err instanceof AuthError) {
          clearToken();
          setAuthed(false);
        } else if (!cancelled) {
          setError('Sunucuya bağlanılamadı. localhost:8788 çalışıyor mu?');
        }
      }
    };

    void tick();
    const id = window.setInterval(() => void tick(), 1000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [authed]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (q.length === 0) {
      return entries;
    }
    return entries.filter(
      (e) =>
        e.ip.toLowerCase().includes(q) ||
        e.hash.toLowerCase().includes(q) ||
        e.reason.toLowerCase().includes(q),
    );
  }, [entries, filter]);

  const handleUnban = (ip: string) => {
    void unban(ip).then(() => {
      setEntries((prev) => prev.map((e) => (e.ip === ip ? { ...e, banned: false } : e)));
    });
  };

  const handleDelete = (hash: string) => {
    void deleteDark(hash).then(() => {
      setEntries((prev) => prev.filter((e) => e.hash !== hash));
    });
  };

  const handleThreshold = (value: number) => {
    setThresholdValue(value);
    void setThreshold(value);
  };

  const handleMode = (value: boolean) => {
    setAggressive(value);
    void setMode(value);
  };

  if (!authed) {
    return <AuthGate onAuthed={() => setAuthed(true)} />;
  }

  return (
    <>
      <header class="topbar">
        <div class="topbar-inner">
          <div class="brand">
            <span class="brand-mark" aria-hidden="true">
              🦊
            </span>
            <div>
              <div>fox-shield</div>
              <div class="brand-sub">Developer Mode</div>
            </div>
          </div>
          <div class="topbar-actions">
            <span class="status-badge">
              <span class="dot" aria-hidden="true" />
              Canlı
            </span>
            <label class="switch">
              <input
                type="checkbox"
                checked={aggressive}
                onChange={(e) => handleMode((e.target as HTMLInputElement).checked)}
              />
              <span class="switch-track" aria-hidden="true" />
              <span class="switch-label">Aggressive</span>
            </label>
            <button
              class="btn btn-sm"
              onClick={() => {
                clearToken();
                setAuthed(false);
              }}
            >
              Çıkış
            </button>
          </div>
        </div>
      </header>

      <main class="shell">
        <section class="hero">
          <h1>Dark List Viewer</h1>
          <p>
            Banlanamayan kötü istekler bile <strong>DESTROY</strong> katmanında yok edilir ve
            origin'e asla ulaşmaz. Aşağıda tüm kara liste kayıtları.
          </p>
        </section>

        {error && <p style={{ color: 'var(--danger)', margin: '0 0 16px' }}>{error}</p>}

        {stats && <Stats stats={stats} />}

        <div class="destroy-banner">
          <span style={{ fontSize: 20 }} aria-hidden="true">
            🛡️
          </span>
          <span>
            <strong>Destroy garantisi:</strong> Bu istek banlanamadı ama DESTROY katmanında yok
            edildi — origin'e ulaşmadı.
          </span>
        </div>

        <div class="controls">
          <div class="search">
            <span aria-hidden="true">🔍</span>
            <input
              type="search"
              placeholder="IP, hash veya reason ile filtrele…"
              value={filter}
              onInput={(e) => setFilter((e.target as HTMLInputElement).value)}
            />
          </div>
          <div class="slider-row" style={{ flex: '0 0 260px' }}>
            <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>Eşik</span>
            <input
              type="range"
              min={0.85}
              max={0.95}
              step={0.01}
              value={threshold}
              aria-label="Benzerlik eşiği"
              onInput={(e) => handleThreshold(Number((e.target as HTMLInputElement).value))}
            />
            <span class="slider-value">{threshold.toFixed(2)}</span>
          </div>
        </div>

        <DarkList entries={filtered} onUnban={handleUnban} onDelete={handleDelete} />

        <footer class="footer">
          <span>fox-shield Developer Mode · localhost:8788 · yalnızca sahibine özel</span>
          <span>Canlı güncelleme: 1 sn</span>
        </footer>
      </main>
    </>
  );
}
