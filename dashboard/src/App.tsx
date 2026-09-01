import { useEffect, useState } from 'preact/hooks';
import { Header } from './components/Header';
import { Sidebar, type NavKey } from './components/Sidebar';
import { Stats } from './components/Stats';
import { AttackMap } from './components/AttackMap';
import { BanList } from './components/BanList';
import { ThresholdSlider } from './components/ThresholdSlider';
import { TestButton } from './components/TestButton';
import { DarkPreview } from './components/DarkPreview';
import { Settings } from './components/Settings';
import {
  fetchStats,
  fetchBans,
  fetchMode,
  setMode,
  fetchThreshold,
  setThreshold,
  unbanIp,
  loadSettings,
  saveSettings,
  settingsJson,
  MOCK_STATS,
} from './api';
import type {
  BanEntry,
  ModeState,
  ShieldSettings,
  ShieldStats,
  ThresholdState,
} from './types';

export function App() {
  const [stats, setStats] = useState<ShieldStats | null>(null);
  const [bans, setBans] = useState<BanEntry[]>([]);
  const [mode, setModeState] = useState<ModeState>({ aggressive: false });
  const [threshold, setThresholdState] = useState<ThresholdState>({ threshold: 0.9 });
  const [live, setLive] = useState(false);
  const [settings, setSettings] = useState<ShieldSettings>(() => loadSettings());
  const [nav, setNav] = useState<NavKey>('overview');
  const [showJson, setShowJson] = useState(false);

  // Poll stats every 2s; fall back to mock data when the API is unavailable.
  useEffect(() => {
    let cancelled = false;

    const tick = async () => {
      const { stats: s, live: isLive } = await fetchStats();
      if (cancelled) {
        return;
      }
      setStats(s);
      setLive(isLive);
    };

    void tick();
    const id = window.setInterval(() => void tick(), 2000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  // Load bans, mode and threshold once.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const [b, m, t] = await Promise.all([fetchBans(), fetchMode(), fetchThreshold()]);
      if (cancelled) {
        return;
      }
      setBans(b);
      setModeState(m);
      setThresholdState(t);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleToggle = (aggressive: boolean) => {
    setModeState({ aggressive });
    void setMode(aggressive);
  };

  const handleThreshold = (value: number) => {
    setThresholdState({ threshold: value });
    void setThreshold(value);
  };

  const handleUnban = (ip: string) => {
    setBans((prev) => prev.filter((b) => b.ip !== ip));
    void unbanIp(ip);
  };

  const handleSettings = (next: ShieldSettings) => {
    setSettings(next);
    saveSettings(next);
  };

  return (
    <>
      <Header mode={mode} live={live} onToggle={handleToggle} />
      <div class="layout">
        <Sidebar active={nav} onNavigate={setNav} />
        <main class="shell">
          {nav === 'overview' && (
            <div class="page">
              <section class="hero">
                <h1>Shield is up.</h1>
                <p>
                  fox-shield is absorbing and neutralizing malicious traffic across the edge.
                  Live telemetry below.
                </p>
              </section>

              {stats && <Stats stats={stats} aggressive={mode.aggressive} />}

              <div class="grid-2">
                <AttackMap stats={stats ?? MOCK_STATS} />
                <BanList bans={bans} onUnban={handleUnban} />
              </div>

              <div class="grid-2">
                <ThresholdSlider value={threshold.threshold} onChange={handleThreshold} />
                <TestButton />
              </div>

              <DarkPreview />
            </div>
          )}

          {nav === 'analytics' && (
            <div class="page">
              <section class="hero">
                <h1>Analytics</h1>
                <p>Traffic and threat telemetry across the edge.</p>
              </section>
              {stats && <Stats stats={stats} aggressive={mode.aggressive} />}
              <div class="grid-2">
                <AttackMap stats={stats ?? MOCK_STATS} />
                <BanList bans={bans} onUnban={handleUnban} />
              </div>
            </div>
          )}

          {nav === 'firewall' && (
            <div class="page">
              <section class="hero">
                <h1>Firewall</h1>
                <p>Configure how fox-shield filters and challenges traffic.</p>
              </section>
              <Settings settings={settings} onChange={handleSettings} />
            </div>
          )}

          {nav === 'tools' && (
            <div class="page">
              <section class="hero">
                <h1>Tools</h1>
                <p>Load testing and developer utilities.</p>
              </section>
              <div class="grid-2">
                <ThresholdSlider value={threshold.threshold} onChange={handleThreshold} />
                <TestButton />
              </div>
              <DarkPreview />
            </div>
          )}

          {nav === 'settings' && (
            <div class="page">
              <section class="hero">
                <h1>Settings</h1>
                <p>Shield configuration. Persisted locally and exposed as JSON for the worker.</p>
              </section>
              <Settings settings={settings} onChange={handleSettings} />

              <section class="card settings-card">
                <h2 class="card-title">Worker config (JSON)</h2>
                <p class="card-desc">
                  Copy this JSON into your edge worker or origin shield to apply the same
                  settings server-side.
                </p>
                <button
                  type="button"
                  class="btn btn-sm"
                  onClick={() => setShowJson((v) => !v)}
                  aria-expanded={showJson}
                >
                  {showJson ? 'Hide JSON' : 'Show JSON'}
                </button>
                {showJson && <pre class="json-block">{settingsJson(settings)}</pre>}
              </section>
            </div>
          )}

          <footer class="footer">
            <span>fox-shield v1.1 · edge + origin shield</span>
            <span>Dark list is private — Developer Mode only</span>
          </footer>
        </main>
      </div>
    </>
  );
}
