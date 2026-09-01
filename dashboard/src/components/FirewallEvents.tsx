/** Realistic firewall event log — Cloudflare-style dense table. */
interface Event {
  time: string;
  ip: string;
  action: 'blocked' | 'challenged' | 'allowed';
  rule: string;
  country: string;
}

const EVENTS: Event[] = [
  { time: '14:02:11', ip: '185.220.101.34', action: 'blocked', rule: 'waf:SQLI-001:sqli', country: 'DE' },
  { time: '14:01:47', ip: '45.155.205.233', action: 'blocked', rule: 'similarity match', country: 'NL' },
  { time: '14:01:03', ip: '103.75.190.21', action: 'challenged', rule: 'rate limit 20 rps', country: 'CN' },
  { time: '13:59:52', ip: '91.240.118.77', action: 'blocked', rule: 'waf:RCE-002:rce', country: 'RU' },
  { time: '13:58:30', ip: '198.98.54.12', action: 'blocked', rule: 'similarity exact match', country: 'US' },
  { time: '13:57:18', ip: '203.0.113.44', action: 'challenged', rule: 'browser integrity', country: 'BR' },
  { time: '13:55:09', ip: '192.0.2.77', action: 'allowed', rule: 'whitelist', country: 'TR' },
];

const ACTION_LABEL: Record<Event['action'], string> = {
  blocked: 'Blocked',
  challenged: 'Challenged',
  allowed: 'Allowed',
};

export function FirewallEvents() {
  return (
    <div class="card">
      <h2 class="card-title">
        Firewall events
        <span class="hint">Last 24 hours</span>
      </h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>IP address</th>
              <th>Action</th>
              <th>Rule</th>
              <th>Country</th>
            </tr>
          </thead>
          <tbody>
            {EVENTS.map((e) => (
              <tr key={`${e.time}-${e.ip}`}>
                <td class="mono">{e.time}</td>
                <td class="mono">{e.ip}</td>
                <td>
                  <span class={`reason ${e.action}`}>{ACTION_LABEL[e.action]}</span>
                </td>
                <td class="mono">{e.rule}</td>
                <td>{e.country}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
