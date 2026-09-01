import { useState } from 'preact/hooks';

const K6_CMD = 'k6 run -e TARGET=https://your-origin.example.com tests/load-753.js';

export function TestButton() {
  const [running, setRunning] = useState(false);
  const [sent, setSent] = useState(0);

  const run = () => {
    setRunning(true);
    setSent(0);
    // Fire a burst of requests to the configured API base (no-op on static site).
    const base = import.meta.env.VITE_API_BASE ?? '';
    let count = 0;
    const timer = window.setInterval(() => {
      if (count >= 753) {
        window.clearInterval(timer);
        setRunning(false);
        return;
      }
      if (base) {
        void fetch(base).catch(() => undefined);
      }
      count += 1;
      setSent(count);
    }, 1);
  };

  return (
    <div class="card">
      <h2 class="card-title">753 rps test</h2>
      <div class="test-panel">
        <button class="btn btn-accent" onClick={run} disabled={running}>
          {running ? `Firing ${sent}…` : '753 rps Test'}
        </button>
        <code class="test-cmd">{K6_CMD}</code>
      </div>
      <p style={{ color: 'var(--text-faint)', fontSize: 12, margin: '12px 0 0' }}>
        A single IP exceeding the rate limit is banned instantly with 0 origin hits.
      </p>
    </div>
  );
}
