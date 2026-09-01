import type { ShieldStats } from '../types';

interface AttackMapProps {
  stats: ShieldStats;
}

/** Top attacking countries as horizontal bars (summary only — no private data). */
export function AttackMap({ stats }: AttackMapProps) {
  const max = Math.max(1, ...stats.topCountries.map((c) => c.count));

  return (
    <div class="card">
      <h2 class="card-title">Top attacking countries</h2>
      {stats.topCountries.map((c) => (
        <div class="bar-row" key={c.country}>
          <span class="bar-label">{c.country}</span>
          <div class="bar-track">
            <div class="bar-fill" style={{ width: `${(c.count / max) * 100}%` }} />
          </div>
          <span class="bar-count">{c.count.toLocaleString('en-US')}</span>
        </div>
      ))}
    </div>
  );
}
