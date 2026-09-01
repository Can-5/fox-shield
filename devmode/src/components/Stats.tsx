import type { DevStats } from '../types';

interface StatsProps {
  stats: DevStats;
}

function format(n: number): string {
  return n.toLocaleString('en-US');
}

export function Stats({ stats }: StatsProps) {
  return (
    <section class="stats-grid" aria-label="Shield statistics">
      <div class="stat">
        <div class="stat-label">Requests / sec</div>
        <div class="stat-value accent">{format(stats.rps)}</div>
      </div>
      <div class="stat">
        <div class="stat-label">Blocked today</div>
        <div class="stat-value">{format(stats.blockedToday)}</div>
      </div>
      <div class="stat">
        <div class="stat-label">Banned IPs</div>
        <div class="stat-value warn">{format(stats.bannedIps)}</div>
      </div>
      <div class="stat">
        <div class="stat-label">Destroyed</div>
        <div class="stat-value ok">{format(stats.destroyed)}</div>
      </div>
    </section>
  );
}
