import type { ModeState } from '../types';

interface HeaderProps {
  mode: ModeState;
  live: boolean;
  onToggle: (aggressive: boolean) => void;
}

export function Header({ mode, live, onToggle }: HeaderProps) {
  return (
    <header class="topbar">
      <div class="topbar-inner">
        <div class="brand">
          <span class="brand-mark" aria-hidden="true">
            🦊
          </span>
          <div>
            <div>fox-shield</div>
            <div class="brand-sub">Shield Dashboard</div>
          </div>
        </div>

        <div class="topbar-actions">
          <span class={`status-badge ${live ? 'live' : 'mock'}`}>
            <span class="dot" aria-hidden="true" />
            {live ? 'Live' : 'Demo data'}
          </span>

          <label class="switch">
            <input
              type="checkbox"
              checked={mode.aggressive}
              onChange={(e) => onToggle((e.target as HTMLInputElement).checked)}
            />
            <span class="switch-track" aria-hidden="true" />
            <span class="switch-label">Aggressive Mode</span>
          </label>
        </div>
      </div>
    </header>
  );
}
