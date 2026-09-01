export type NavKey = 'overview' | 'analytics' | 'firewall' | 'tools' | 'settings';

interface SidebarProps {
  active: NavKey;
  onNavigate: (key: NavKey) => void;
}

const NAV_ITEMS: Array<{ key: NavKey; label: string; icon: string }> = [
  { key: 'overview', label: 'Overview', icon: '◈' },
  { key: 'analytics', label: 'Analytics', icon: '▤' },
  { key: 'firewall', label: 'Firewall', icon: '⛨' },
  { key: 'tools', label: 'Tools', icon: '⚙' },
  { key: 'settings', label: 'Settings', icon: '☰' },
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
                {item.icon}
              </span>
              <span>{item.label}</span>
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}
