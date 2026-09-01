/** 24h traffic sparkline — Cloudflare-style area chart. */
export function TrafficChart() {
  // Mock 24h request volume (per hour). Non-round, realistic.
  const data = [
    4120, 3880, 4210, 4550, 4020, 4760, 5030, 4680, 5210, 4970, 5400, 5120,
    5880, 5610, 6040, 5770, 6310, 5980, 6620, 6400, 7050, 6830, 7260, 7530,
  ];
  const w = 640;
  const h = 140;
  const pad = 4;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const step = (w - pad * 2) / (data.length - 1);
  const coords = data.map((p, i) => {
    const x = pad + i * step;
    const y = h - pad - ((p - min) / range) * (h - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const line = coords.join(' ');
  const area = `${pad},${h - pad} ${line} ${w - pad},${h - pad}`;

  return (
    <div class="chart-wrap">
      <svg
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="Requests over the last 24 hours"
      >
        <defs>
          <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.18" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <polygon points={area} fill="url(#trafficFill)" />
        <polyline
          points={line}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      </svg>
      <div class="chart-legend">
        <span class="lg">
          <span class="sw" style={{ background: 'var(--accent)' }} />
          Requests
        </span>
        <span class="lg">Peak 7,530 / hr</span>
        <span class="lg">Avg 5,612 / hr</span>
      </div>
    </div>
  );
}
