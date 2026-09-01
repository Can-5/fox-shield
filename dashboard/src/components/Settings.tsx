import type {
  CacheLevel,
  SecurityLevel,
  ShieldSettings,
  WafSensitivity,
} from '../types';

interface SettingsProps {
  settings: ShieldSettings;
  onChange: (settings: ShieldSettings) => void;
}

const SECURITY_LEVELS: Array<{ value: SecurityLevel; label: string }> = [
  { value: 'off', label: 'Off' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'under_attack', label: "I'm Under Attack" },
];

const CACHE_LEVELS: Array<{ value: CacheLevel; label: string }> = [
  { value: 'bypass', label: 'Bypass' },
  { value: 'standard', label: 'Standard' },
  { value: 'aggressive', label: 'Aggressive' },
];

const WAF_SENSITIVITY: Array<{ value: WafSensitivity; label: string }> = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
];

const COUNTRIES = [
  'TR',
  'DE',
  'US',
  'RU',
  'CN',
  'BR',
  'NL',
  'FR',
  'GB',
  'IN',
  'UA',
  'IR',
  'KP',
  'HK',
];

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
}) {
  return (
    <label class="cf-toggle">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange((e.target as HTMLInputElement).checked)}
      />
      <span class="cf-toggle-track" aria-hidden="true" />
      <span class="cf-toggle-label">{label}</span>
    </label>
  );
}

function RadioGroup<T extends string>({
  value,
  options,
  onChange,
  name,
}: {
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (value: T) => void;
  name: string;
}) {
  return (
    <div class="cf-radio-group" role="radiogroup" aria-label={name}>
      {options.map((opt) => (
        <label class="cf-radio" key={opt.value}>
          <input
            type="radio"
            name={name}
            value={opt.value}
            checked={value === opt.value}
            onChange={() => onChange(opt.value)}
          />
          <span class="cf-radio-dot" aria-hidden="true" />
          <span>{opt.label}</span>
        </label>
      ))}
    </div>
  );
}

export function Settings({ settings, onChange }: SettingsProps) {
  const set = <K extends keyof ShieldSettings>(key: K, value: ShieldSettings[K]) => {
    onChange({ ...settings, [key]: value });
  };

  const toggleGeo = (code: string) => {
    const next = settings.geoBlock.includes(code)
      ? settings.geoBlock.filter((c) => c !== code)
      : [...settings.geoBlock, code];
    set('geoBlock', next);
  };

  return (
    <div class="settings">
      <section class="card settings-card">
        <h2 class="card-title">Security Level</h2>
        <p class="card-desc">
          Choose how aggressively fox-shield challenges visitors. Higher levels block more
          automated traffic.
        </p>
        <RadioGroup
          name="security-level"
          value={settings.securityLevel}
          options={SECURITY_LEVELS}
          onChange={(v) => set('securityLevel', v)}
        />
      </section>

      <section class="card settings-card">
        <h2 class="card-title">Bot Fight Mode</h2>
        <p class="card-desc">
          Automatically challenge requests that match known bot signatures.
        </p>
        <Toggle
          checked={settings.botFightMode}
          onChange={(v) => set('botFightMode', v)}
          label="Bot Fight Mode"
        />
      </section>

      <section class="card settings-card">
        <h2 class="card-title">Challenge Passage</h2>
        <p class="card-desc">
          How long a visitor who passes a challenge stays verified before being re-checked.
        </p>
        <div class="slider-row">
          <input
            type="range"
            min={10}
            max={60}
            step={5}
            value={settings.challengePassage}
            aria-label="Challenge passage minutes"
            onInput={(e) => set('challengePassage', Number((e.target as HTMLInputElement).value))}
          />
          <span class="slider-value">{settings.challengePassage}m</span>
        </div>
      </section>

      <section class="card settings-card">
        <h2 class="card-title">Cache Level</h2>
        <p class="card-desc">
          How aggressively fox-shield caches responses at the edge.
        </p>
        <RadioGroup
          name="cache-level"
          value={settings.cacheLevel}
          options={CACHE_LEVELS}
          onChange={(v) => set('cacheLevel', v)}
        />
      </section>

      <section class="card settings-card">
        <h2 class="card-title">Browser Integrity Check</h2>
        <p class="card-desc">
          Reject requests that fail a browser integrity challenge.
        </p>
        <Toggle
          checked={settings.browserIntegrityCheck}
          onChange={(v) => set('browserIntegrityCheck', v)}
          label="Browser Integrity Check"
        />
      </section>

      <section class="card settings-card">
        <h2 class="card-title">IP Whitelist</h2>
        <p class="card-desc">
          IPs that are always allowed through, one per line. Supports CIDR ranges.
        </p>
        <textarea
          class="cf-textarea"
          rows={4}
          value={settings.ipWhitelist}
          placeholder={'127.0.0.1\n192.168.0.0/16'}
          aria-label="IP whitelist"
          onInput={(e) => set('ipWhitelist', (e.target as HTMLTextAreaElement).value)}
        />
      </section>

      <section class="card settings-card">
        <h2 class="card-title">Geo Blocking</h2>
        <p class="card-desc">
          Block traffic from selected countries. Click to toggle.
        </p>
        <div class="cf-chips">
          {COUNTRIES.map((code) => (
            <button
              type="button"
              class={`cf-chip ${settings.geoBlock.includes(code) ? 'active' : ''}`}
              key={code}
              onClick={() => toggleGeo(code)}
              aria-pressed={settings.geoBlock.includes(code)}
            >
              {code}
            </button>
          ))}
        </div>
      </section>

      <section class="card settings-card">
        <h2 class="card-title">WAF Sensitivity</h2>
        <p class="card-desc">
          How aggressively the Web Application Firewall flags and blocks requests.
        </p>
        <RadioGroup
          name="waf-sensitivity"
          value={settings.wafSensitivity}
          options={WAF_SENSITIVITY}
          onChange={(v) => set('wafSensitivity', v)}
        />
      </section>

      <section class="card settings-card">
        <h2 class="card-title">Daily Block Quota</h2>
        <p class="card-desc">
          Maximum blocks per day before the shield hard-stops to protect the origin.
        </p>
        <div class="quota-row">
          <input
            class="cf-number"
            type="number"
            min={1000}
            step={1000}
            value={settings.dailyBlockQuota}
            aria-label="Daily block quota"
            onInput={(e) =>
              set('dailyBlockQuota', Math.max(0, Number((e.target as HTMLInputElement).value)))
            }
          />
          <span class="quota-hint">blocks / day</span>
        </div>
      </section>
    </div>
  );
}
