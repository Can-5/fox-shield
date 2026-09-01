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
import { TrafficChart } from './components/TrafficChart';
import { FirewallEvents } from './components/FirewallEvents';
import { ActivityLog } from './components/ActivityLog';
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

/** Cloudflare-style page header with breadcrumb + "Last updated". */
function PageHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div class="page-head">
      <div>
        <h1>{title}</h1>
        <p class="sub">{sub}</p>
      </div>
      <span class="updated">Last updated: 2 min ago</span>
    </div>
  );
}

/** Quick actions rail — Cloudflare-style shortcuts. */
function QuickActions() {
  return (
    <div class="card">
      <h2 class="card-title">Quick actions</h2>
      <div class="quick-actions">
        <a class="qa" href="#firewall">
          <span class="qa-icon" aria-hidden="true">⚙</span>
          Configure firewall
          <span class="qa-arrow" aria-hidden="true">›</span>
        </a>
        <a class="qa" href="#analytics">
          <span class="qa-icon" aria-hidden="true">▤</span>
          View analytics
          <span class="qa-arrow" aria-hidden="true">›</span>
        </a>
        <a class="qa" href="#tools">
          <span class="qa-icon" aria-hidden="true">⚡</span>
          Run load test
          <span class="qa-arrow" aria-hidden="true">›</span>
        </a>
        <a class="qa" href="http://localhost:8788" target="_blank" rel="noreferrer">
          <span class="qa-icon" aria-hidden="true">⌘</span>
          Developer Mode
          <span class="qa-arrow" aria-hidden="true">›</span>
        </a>
      </div>
    </div>
  );
}

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
              <PageHead
                title="Overview"
                sub="Traffic and threat telemetry for fox-shield."
              />

              {stats && <Stats stats={stats} aggressive={mode.aggressive} />}

              <div class="grid-3">
                <div class="card">
                  <h2 class="card-title">
                    Traffic
                    <span class="hint">Last 24 hours</span>
                  </h2>
                  <TrafficChart />
                </div>
                <QuickActions />
              </div>

              <div class="grid-2">
                <FirewallEvents />
                <ActivityLog />
              </div>

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
              <PageHead title="Analytics" sub="Traffic and threat telemetry across the edge." />
              {stats && <Stats stats={stats} aggressive={mode.aggressive} />}
              <div class="grid-2">
                <AttackMap stats={stats ?? MOCK_STATS} />
                <BanList bans={bans} onUnban={handleUnban} />
              </div>
            </div>
          )}

          {nav === 'firewall' && (
            <div class="page">
              <PageHead
                title="Firewall"
                sub="Configure how fox-shield filters and challenges traffic."
              />
              <Settings settings={settings} onChange={handleSettings} />
            </div>
          )}

          {nav === 'tools' && (
            <div class="page">
              <PageHead title="Tools" sub="Load testing and developer utilities." />
              <div class="grid-2">
                <ThresholdSlider value={threshold.threshold} onChange={handleThreshold} />
                <TestButton />
              </div>
              <DarkPreview />
            </div>
          )}

          {nav === 'settings' && (
            <div class="page">
              <PageHead
                title="Settings"
                sub="Shield configuration. Persisted locally and exposed as JSON for the worker."
              />
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
            <div class="links">
              <a href="#overview">Overview</a>
              <a href="#firewall">Firewall</a>
              <a href="#settings">Settings</a>
              <a href="https://developers.cloudflare.com" target="_blank" rel="noreferrer">
                Help
              </a>
            </div>
          </footer>
        </main>
      </div>
    </>
  );
}
