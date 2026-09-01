import { useEffect, useState } from 'preact/hooks';
import { Header } from './components/Header';
import { Stats } from './components/Stats';
import { AttackMap } from './components/AttackMap';
import { BanList } from './components/BanList';
import { ThresholdSlider } from './components/ThresholdSlider';
import { TestButton } from './components/TestButton';
import { DarkPreview } from './components/DarkPreview';
import {
  fetchStats,
  fetchBans,
  fetchMode,
  setMode,
  fetchThreshold,
  setThreshold,
  unbanIp,
  MOCK_STATS,
} from './api';
import type { BanEntry, ModeState, ShieldStats, ThresholdState } from './types';

export function App() {
  const [stats, setStats] = useState<ShieldStats | null>(null);
  const [bans, setBans] = useState<BanEntry[]>([]);
  const [mode, setModeState] = useState<ModeState>({ aggressive: false });
  const [threshold, setThresholdState] = useState<ThresholdState>({ threshold: 0.9 });
  const [live, setLive] = useState(false);

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

  return (
    <>
      <Header mode={mode} live={live} onToggle={handleToggle} />
      <main class="shell">
        <section class="hero">
          <h1>Shield is up.</h1>
          <p>
            fox-shield is absorbing and neutralizing malicious traffic across the edge. Live
            telemetry below.
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

        <footer class="footer">
          <span>fox-shield v1.0 · edge + origin shield</span>
          <span>Dark list is private — Developer Mode only</span>
        </footer>
      </main>
    </>
  );
}
