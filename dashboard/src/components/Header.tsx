import type { ModeState } from '../types';

interface HeaderProps {
  mode: ModeState;
  live: boolean;
  onToggle: (aggressive: boolean) => void;
}

/** Small inline SVG fox mark — subtle, not a big emoji. */
function FoxMark() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3c-3 1.5-5 1.5-7 1 1 2.5 1.5 4.5 1 7-.8 3.5 1.5 7 6 9 4.5-2 6.8-5.5 6-9-.5-2.5 0-4.5 1-7-2 .5-4 .5-7-1z"
        fill="currentColor"
      />
      <circle cx="9.5" cy="11" r="1" fill="#1a0a05" />
      <circle cx="14.5" cy="11" r="1" fill="#1a0a05" />
    </svg>
  );
}

export function Header({ mode, live, onToggle }: HeaderProps) {
  return (
    <header class="topbar">
      <div class="topbar-inner">
        <div class="brand">
          <span class="brand-mark" aria-hidden="true">
            <FoxMark />
          </span>
          <div class="crumb">
            <span class="crumb-account" title="Switch account">
              Kygszilkaycan@icloud.com
              <span class="caret" aria-hidden="true">▾</span>
            </span>
            <span class="sep" aria-hidden="true">/</span>
            <span class="crumb-domain">fox-shield</span>
          </div>
          <span class="plan-text">Free</span>
        </div>

        <div class="topbar-actions">
          <span class={`status-badge ${live ? 'live' : 'mock'}`}>
            <span class="dot" aria-hidden="true" />
            {live ? 'Live' : 'Demo data'}
          </span>

          <label class="switch under-attack">
            <input
              type="checkbox"
              checked={mode.aggressive}
              onChange={(e) => onToggle((e.target as HTMLInputElement).checked)}
            />
            <span class="switch-track" aria-hidden="true" />
            <span class="switch-label">Under Attack</span>
          </label>

          <button type="button" class="icon-btn" title="Help" aria-label="Help">
            ?
          </button>
          <button type="button" class="icon-btn" title="Notifications" aria-label="Notifications">
            <svg viewBox="0 0 16 16" width="15" height="15" fill="currentColor" aria-hidden="true">
              <path d="M8 1.5a4.5 4.5 0 0 0-4.5 4.5v2.2L2.2 10.5a.75.75 0 0 0 .55 1.25h10.5a.75.75 0 0 0 .55-1.25L12.5 8.2V6A4.5 4.5 0 0 0 8 1.5zM6.5 13a1.5 1.5 0 0 0 3 0h-3z" />
            </svg>
          </button>
          <button type="button" class="icon-btn" title="Account" aria-label="Account">
            <svg viewBox="0 0 16 16" width="15" height="15" fill="currentColor" aria-hidden="true">
              <circle cx="8" cy="5" r="3" />
              <path d="M2.5 14a5.5 5.5 0 0 1 11 0H2.5z" />
            </svg>
          </button>
        </div>
      </div>
    </header>
  );
}
