import { useEffect, useMemo, useState } from 'preact/hooks';
import { AuthGate } from './components/AuthGate';
import { Stats } from './components/Stats';
import { DarkList } from './components/DarkList';
import { AdminPanel } from './components/AdminPanel';
import {
  fetchDark,
  fetchStats,
  fetchSettings,
  fetchSystem,
  unban,
  deleteDark,
  setThreshold,
  setMode,
  getToken,
  clearToken,
  getDeviceId,
  AuthError,
  DeviceError,
} from './api';
import type { DarkEntry, DevStats, ShieldSettings, SystemInfo } from './types';

const DEFAULT_SETTINGS: ShieldSettings = {
  securityLevel: 'medium',
  botFightMode: true,
  challengePassage: 30,
  cacheLevel: 'standard',
  browserIntegrityCheck: true,
  ipWhitelist: '',
  geoBlock: [],
  wafSensitivity: 'medium',
  dailyBlockQuota: 50000,
  dailyChallengeLimit: 100000,
  unlimited: false,
  normalRps: 20,
  aggressiveRps: 10,
  burst: 40,
  aggressiveBurst: 20,
  windowMs: 1000,
  difficultyNormal: 4,
  difficultyAggressive: 5,
  banNormalMinutes: 10,
  banAggressiveMinutes: 60,
  threshold: 0.9,
  aggressiveThreshold: 0.85,
};

export function App() {
  const [authed, setAuthed] = useState(() => getToken().length > 0);
  const [entries, setEntries] = useState<DarkEntry[]>([]);
  const [stats, setStats] = useState<DevStats | null>(null);
  const [settings, setSettings] = useState<ShieldSettings>(DEFAULT_SETTINGS);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [filter, setFilter] = useState('');
  const [threshold, setThresholdValue] = useState(0.9);
  const [aggressive, setAggressive] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState<{ msg: string; kind: 'ok' | 'err' } | null>(null);
  const [deviceError, setDeviceError] = useState(false);

  const deviceId = getDeviceId();

  const notify = (msg: string, kind: 'ok' | 'err' = 'ok') => {
    setNotice({ msg, kind });
    window.setTimeout(() => setNotice(null), 4000);
  };

  // Live tail — poll every 1s for new bans / stats / system.
  useEffect(() => {
    if (!authed) {
      return;
    }
    let cancelled = false;

    const tick = async () => {
      try {
        const [d, s, sys] = await Promise.all([fetchDark(), fetchStats(), fetchSystem()]);
        if (cancelled) {
          return;
        }
        setEntries(d);
        setStats(s);
        setSystem(sys);
        setThresholdValue(s.threshold);
        setAggressive(s.aggressive);
        setError('');
      } catch (err) {
        if (err instanceof AuthError) {
          clearToken();
          setAuthed(false);
        } else if (err instanceof DeviceError) {
          setDeviceError(true);
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

  // Load settings once on auth.
  useEffect(() => {
    if (!authed) {
      return;
    }
    void fetchSettings()
      .then(setSettings)
      .catch(() => {
        // Settings load failure is non-fatal — defaults remain.
      });
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

  const isCloud = system?.mode === 'cloud' || system?.allowRemote === true;

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
            {isCloud ? (
              <span class="status-badge cloud" title="Özel bulut — token korumalı">
                ☁️ Private Cloud
              </span>
            ) : (
              <span class="status-badge lock" title="Cihaz bağlama aktif">
                🔒 Sadece bu PC — Device: {deviceId.slice(0, 7)}
              </span>
            )}
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
        {deviceError && (
          <div class="device-error">
            <strong>🔒 Bu cihaz bağlı değil.</strong> DevMode yalnızca sahibinin PC'sinde çalışır.
            Başka bir cihazdan erişim engellendi.
          </div>
        )}

        {notice && (
          <div class={`notice ${notice.kind}`} role="status">
            {notice.msg}
          </div>
        )}

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

        <section class="admin-section">
          <h2 class="section-title">⚙️ Tam Yönetim Paneli</h2>
          <AdminPanel
            settings={settings}
            system={system}
            onSettingsChange={setSettings}
            onSystemChange={setSystem}
            onNotify={notify}
          />
        </section>

        <footer class="footer">
          <span>
            fox-shield Developer Mode · {isCloud ? '☁️ özel bulut' : 'localhost:8788'} ·{' '}
            {isCloud ? 'token korumalı' : 'yalnızca sahibine özel'}
          </span>
          <span>Canlı güncelleme: 1 sn</span>
        </footer>
      </main>
    </>
  );
}
