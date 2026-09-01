/** Recent activity timeline — Cloudflare-style, realistic timestamps. */
interface Activity {
  time: string;
  text: string;
  strong?: string;
  text2?: string;
}

const ACTIVITY: Activity[] = [
  { time: '14:02', text: 'IP ', strong: '185.220.101.34', text2: ' banned — SQL injection attempt' },
  { time: '14:01', text: 'Rate limit triggered for ', strong: '103.75.190.21' },
  { time: '13:59', text: 'IP ', strong: '91.240.118.77', text2: ' banned — RCE attempt' },
  { time: '13:55', text: 'Whitelist match for ', strong: '192.0.2.77' },
  { time: '13:48', text: 'Under Attack mode ', strong: 'disabled' },
  { time: '13:12', text: 'Similarity threshold set to ', strong: '0.90' },
];

export function ActivityLog() {
  return (
    <div class="card">
      <h2 class="card-title">
        Recent activity
        <span class="hint">Today</span>
      </h2>
      <ul class="activity">
        {ACTIVITY.map((a, i) => (
          <li key={i}>
            <span class="t">{a.time}</span>
            <span class="ev">
              {a.text}
              {a.strong && <b>{a.strong}</b>}
              {a.text2}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
