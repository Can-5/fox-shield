import type { ShieldStats } from '../types';

interface StatsProps {
  stats: ShieldStats;
  aggressive: boolean;
}

function format(n: number): string {
  return n.toLocaleString('en-US');
}

/** Tiny inline sparkline for the requests/sec card. */
function Sparkline({ points }: { points: number[] }) {
  const w = 120;
  const h = 28;
  const max = Math.max(...points);
  const min = Math.min(...points);
  const range = max - min || 1;
  const step = w / (points.length - 1);
  const coords = points.map((p, i) => {
    const x = i * step;
    const y = h - ((p - min) / range) * (h - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const line = coords.join(' ');
  const area = `0,${h} ${line} ${w},${h}`;
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      width="100%"
      height={h}
      preserveAspectRatio="none"
      aria-hidden="true"
      style={{ display: 'block', marginTop: 8 }}
    >
      <polygon points={area} fill="rgba(246,130,31,0.12)" />
      <polyline
        points={line}
        fill="none"
        stroke="var(--accent)"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function Stats({ stats, aggressive }: StatsProps) {
  return (
    <section class="stats-grid" aria-label="Live shield statistics">
      <div class="stat">
        <div class="stat-label">Requests / sec</div>
        <div class="stat-value accent">{format(stats.rps)}</div>
        <div class="stat-sub">{aggressive ? 'Aggressive limit 10 rps' : 'Normal limit 20 rps'}</div>
        <Sparkline points={[412, 388, 421, 455, 402, 476, 503, 468, 521, 497, 540, 512, 588, 561, 604, 577, 631, 598, 662, 640, 705, 683, 726, 753]} />
      </div>
      <div class="stat">
        <div class="stat-label">Blocked today</div>
        <div class="stat-value">{format(stats.blockedToday)}</div>
        <div class="stat-sub">WAF + similarity + rate limit</div>
      </div>
      <div class="stat tall">
        <div class="stat-label">Banned IPs</div>
        <div class="stat-value warn">{format(stats.bannedIps)}</div>
        <div class="stat-sub">Active bans</div>
      </div>
      <div class="stat">
        <div class="stat-label">Destroyed</div>
        <div class="stat-value ok">{format(stats.destroyed)}</div>
        <div class="stat-sub">Never reached origin</div>
      </div>
    </section>
  );
}
