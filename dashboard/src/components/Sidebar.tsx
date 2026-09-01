export type NavKey = 'overview' | 'analytics' | 'firewall' | 'tools' | 'settings';

interface SidebarProps {
  active: NavKey;
  onNavigate: (key: NavKey) => void;
}

/** Minimal Cloudflare-style line icons. */
function Icon({ name }: { name: NavKey }) {
  const common = {
    width: 18,
    height: 18,
    viewBox: '0 0 18 18',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.5,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  };
  switch (name) {
    case 'overview':
      return (
        <svg {...common} aria-hidden="true">
          <rect x="2.5" y="2.5" width="5" height="5" rx="1" />
          <rect x="10.5" y="2.5" width="5" height="5" rx="1" />
          <rect x="2.5" y="10.5" width="5" height="5" rx="1" />
          <rect x="10.5" y="10.5" width="5" height="5" rx="1" />
        </svg>
      );
    case 'analytics':
      return (
        <svg {...common} aria-hidden="true">
          <path d="M3 15V9" />
          <path d="M7.5 15V5" />
          <path d="M12 15V7.5" />
          <path d="M16 15V3" />
        </svg>
      );
    case 'firewall':
      return (
        <svg {...common} aria-hidden="true">
          <path d="M9 2.5 15 5v4c0 3.5-2.5 5.5-6 6.5C5.5 14.5 3 12.5 3 9V5l6-2.5z" />
          <path d="M6.5 9l1.8 1.8L11.5 7" />
        </svg>
      );
    case 'tools':
      return (
        <svg {...common} aria-hidden="true">
          <circle cx="9" cy="9" r="2.5" />
          <path d="M9 2.5v2M9 13.5v2M2.5 9h2M13.5 9h2M4.4 4.4l1.4 1.4M12.2 12.2l1.4 1.4M13.6 4.4l-1.4 1.4M5.8 12.2l-1.4 1.4" />
        </svg>
      );
    case 'settings':
      return (
        <svg {...common} aria-hidden="true">
          <circle cx="9" cy="9" r="2.2" />
          <path d="M9 2.5v2M9 13.5v2M2.5 9h2M13.5 9h2M4.4 4.4l1.4 1.4M12.2 12.2l1.4 1.4M13.6 4.4l-1.4 1.4M5.8 12.2l-1.4 1.4" />
        </svg>
      );
  }
}

const NAV_ITEMS: Array<{ key: NavKey; label: string }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'analytics', label: 'Analytics' },
  { key: 'firewall', label: 'Firewall' },
  { key: 'tools', label: 'Tools' },
  { key: 'settings', label: 'Settings' },
];

export function Sidebar({ active, onNavigate }: SidebarProps) {
  return (
    <nav class="sidebar" aria-label="Primary">
      <ul class="sidebar-list">
        {NAV_ITEMS.map((item) => (
          <li key={item.key}>
            <button
              type="button"
              class={`sidebar-item ${active === item.key ? 'active' : ''}`}
              onClick={() => onNavigate(item.key)}
              aria-current={active === item.key ? 'page' : undefined}
            >
              <span class="sidebar-icon" aria-hidden="true">
                <Icon name={item.key} />
              </span>
              <span class="tip" role="tooltip">
                {item.label}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}
