import type { ShieldStats } from '../types';

interface StatsProps {
  stats: ShieldStats;
  aggressive: boolean;
}

function format(n: number): string {
  return n.toLocaleString('en-US');
}

export function Stats({ stats, aggressive }: StatsProps) {
  return (
    <section class="stats-grid" aria-label="Live shield statistics">
      <div class="stat">
        <div class="stat-label">Requests / sec</div>
        <div class="stat-value accent">{format(stats.rps)}</div>
        <div class="stat-sub">{aggressive ? 'Aggressive limit 10 rps' : 'Normal limit 20 rps'}</div>
      </div>
      <div class="stat">
        <div class="stat-label">Blocked today</div>
        <div class="stat-value">{format(stats.blockedToday)}</div>
        <div class="stat-sub">WAF + similarity + rate limit</div>
      </div>
      <div class="stat">
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
