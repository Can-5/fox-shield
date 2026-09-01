import type { BanEntry } from '../types';

interface BanListProps {
  bans: BanEntry[];
  onUnban: (ip: string) => void;
}

function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function BanList({ bans, onUnban }: BanListProps) {
  return (
    <div class="card">
      <h2 class="card-title">Active bans</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>IP</th>
              <th>Reason</th>
              <th>Time</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {bans.map((b) => (
              <tr key={b.ip}>
                <td class="mono">{b.ip}</td>
                <td>
                  <span class="reason">{b.reason}</span>
                </td>
                <td class="mono">{formatTime(b.time)}</td>
                <td>
                  <button class="btn btn-sm btn-danger" onClick={() => onUnban(b.ip)}>
                    Unban
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
