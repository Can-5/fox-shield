import { useState } from 'preact/hooks';
import type { ShieldSettings, SystemInfo } from '../types';
import {
  saveSettings,
  whitelist,
  setGeo,
  clearBans,
  resetRules,
  factoryReset,
  deploy,
  ban,
} from '../api';

interface AdminPanelProps {
  settings: ShieldSettings;
  system: SystemInfo | null;
  onSettingsChange: (s: ShieldSettings) => void;
  onSystemChange: (s: SystemInfo) => void;
  onNotify: (msg: string, kind?: 'ok' | 'err') => void;
}

const SECURITY_LEVELS = [
  { value: 'off', label: 'Off' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'under_attack', label: "I'm Under Attack" },
] as const;

const CACHE_LEVELS = [
  { value: 'bypass', label: 'Bypass' },
  { value: 'standard', label: 'Standard' },
  { value: 'aggressive', label: 'Aggressive' },
] as const;

const WAF_SENSITIVITY = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
] as const;

const COUNTRIES = [
  'TR', 'DE', 'US', 'RU', 'CN', 'BR', 'NL', 'FR', 'GB', 'IN', 'UA', 'IR', 'KP', 'HK',
];

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
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
  options: ReadonlyArray<{ value: T; label: string }>;
  onChange: (v: T) => void;
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

function NumberField({
  label,
  value,
  onChange,
  min,
  max,
  step,
  hint,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  step?: number;
  hint?: string;
}) {
  return (
    <div class="cf-field">
      <label class="cf-field-label">{label}</label>
      <input
        class="cf-number"
        type="number"
        min={min}
        max={max}
        step={step}
        value={value}
        onInput={(e) => onChange(Number((e.target as HTMLInputElement).value))}
      />
      {hint && <span class="cf-field-hint">{hint}</span>}
    </div>
  );
}

function formatBytes(n: number): string {
  if (n >= 1024 * 1024 * 1024) return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function formatUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}g ${h}s`;
  if (h > 0) return `${h}s ${m}d`;
  return `${m}d`;
}

export function AdminPanel({
  settings,
  system,
  onSettingsChange,
  onSystemChange,
  onNotify,
}: AdminPanelProps) {
  const [whitelistInput, setWhitelistInput] = useState('');
  const [banIp, setBanIp] = useState('');
  const [banReason, setBanReason] = useState('');
  const [confirmDanger, setConfirmDanger] = useState('');

  const set = <K extends keyof ShieldSettings>(key: K, value: ShieldSettings[K]) => {
    onSettingsChange({ ...settings, [key]: value });
  };

  const persist = async () => {
    try {
      await saveSettings(settings);
      onNotify('Ayarlar kaydedildi ve rules.toml güncellendi.', 'ok');
    } catch {
      onNotify('Ayarlar kaydedilemedi.', 'err');
    }
  };

  const toggleGeo = (code: string) => {
    const next = settings.geoBlock.includes(code)
      ? settings.geoBlock.filter((c) => c !== code)
      : [...settings.geoBlock, code];
    set('geoBlock', next);
    void setGeo(next)
      .then(() => onNotify(`Geo: ${next.length} ülke engellendi.`, 'ok'))
      .catch(() => onNotify('Geo güncellenemedi.', 'err'));
  };

  const addWhitelist = () => {
    const ip = whitelistInput.trim();
    if (!ip) return;
    void whitelist(ip, 'add')
      .then((r) => {
        set('ipWhitelist', r.whitelist.join('\n'));
        setWhitelistInput('');
        onNotify(`${ip} beyaz listeye eklendi.`, 'ok');
      })
      .catch(() => onNotify('Whitelist güncellenemedi.', 'err'));
  };

  const removeWhitelist = (ip: string) => {
    void whitelist(ip, 'remove')
      .then((r) => {
        set('ipWhitelist', r.whitelist.join('\n'));
        onNotify(`${ip} beyaz listeden çıkarıldı.`, 'ok');
      })
      .catch(() => onNotify('Whitelist güncellenemedi.', 'err'));
  };

  const doBan = () => {
    const ip = banIp.trim();
    if (!ip) return;
    void ban(ip, banReason.trim() || 'manual ban')
      .then(() => {
        setBanIp('');
        setBanReason('');
        onNotify(`${ip} banlandı.`, 'ok');
      })
      .catch(() => onNotify('Ban uygulanamadı.', 'err'));
  };

  const doClearBans = () => {
    void clearBans()
      .then(() => onNotify('Tüm banlar temizlendi.', 'ok'))
      .catch(() => onNotify('Banlar temizlenemedi.', 'err'));
  };

  const doResetRules = () => {
    if (confirmDanger !== 'RESET') {
      onNotify('Onaylamak için "RESET" yazın.', 'err');
      return;
    }
    void resetRules()
      .then(() => {
        setConfirmDanger('');
        onNotify('Kurallar varsayılana döndü. Sayfayı yenileyin.', 'ok');
      })
      .catch(() => onNotify('Sıfırlama başarısız.', 'err'));
  };

  const doFactoryReset = () => {
    if (confirmDanger !== 'FACTORY') {
      onNotify('Onaylamak için "FACTORY" yazın.', 'err');
      return;
    }
    void factoryReset()
      .then(() => {
        setConfirmDanger('');
        onNotify('Fabrika ayarlarına dönüldü. Sayfayı yenileyin.', 'ok');
      })
      .catch(() => onNotify('Fabrika sıfırlama başarısız.', 'err'));
  };

  const doDeploy = () => {
    void deploy()
      .then((r) => onNotify(r.instructions, 'ok'))
      .catch(() => onNotify('Deploy bilgisi alınamadı.', 'err'));
  };

  const quotaLimit = system?.unlimited ? Infinity : (system?.quotaLimit ?? settings.dailyBlockQuota);
  const quotaUsed = system?.blockedToday ?? 0;
  const quotaPct = quotaLimit === Infinity ? 0 : Math.min(100, (quotaUsed / quotaLimit) * 100);

  return (
    <div class="admin">
      {/* System stats */}
      <section class="card settings-card">
        <h2 class="card-title">🖥️ Sistem</h2>
        <div class="sys-grid">
          <div class="sys-item">
            <span class="sys-label">Device ID</span>
            <span class="sys-value mono">{system?.deviceId ?? '—'}</span>
          </div>
          <div class="sys-item">
            <span class="sys-label">Uptime</span>
            <span class="sys-value">{system ? formatUptime(system.uptime) : '—'}</span>
          </div>
          <div class="sys-item">
            <span class="sys-label">Bellek (RSS)</span>
            <span class="sys-value">{system ? formatBytes(system.memory.rss) : '—'}</span>
          </div>
          <div class="sys-item">
            <span class="sys-label">Mod</span>
            <span class="sys-value">{system?.mode === 'cloud' ? '☁️ Cloud' : '💻 Local'}</span>
          </div>
        </div>
        <div class="quota-block">
          <div class="quota-head">
            <span>Günlük blok kotası</span>
            <span class="mono">
              {system?.unlimited
                ? 'Sınırsız'
                : `${(quotaUsed / 1000).toFixed(1)}K / ${(quotaLimit / 1000).toFixed(0)}K kullanıldı`}
            </span>
          </div>
          <div class="quota-bar">
            <div class="quota-fill" style={{ width: `${quotaPct}%` }} />
          </div>
          {!system?.unlimited && (
            <div class="quota-remain mono">
              Kalan: {((system?.quotaRemaining ?? 0) / 1000).toFixed(1)}K blok
            </div>
          )}
        </div>
      </section>

      {/* Security level */}
      <section class="card settings-card">
        <h2 class="card-title">🛡️ Security Level</h2>
        <RadioGroup
          name="security-level"
          value={settings.securityLevel}
          options={SECURITY_LEVELS}
          onChange={(v) => set('securityLevel', v)}
        />
      </section>

      {/* Limits */}
      <section class="card settings-card">
        <h2 class="card-title">⚙️ Limitler</h2>
        <div class="cf-grid">
          <NumberField label="Normal RPS" value={settings.normalRps} min={1} onChange={(v) => set('normalRps', v)} />
          <NumberField label="Aggressive RPS" value={settings.aggressiveRps} min={1} onChange={(v) => set('aggressiveRps', v)} />
          <NumberField label="Burst" value={settings.burst} min={1} onChange={(v) => set('burst', v)} />
          <NumberField label="Aggressive Burst" value={settings.aggressiveBurst} min={1} onChange={(v) => set('aggressiveBurst', v)} />
          <NumberField label="Window (ms)" value={settings.windowMs} min={100} step={100} onChange={(v) => set('windowMs', v)} />
        </div>
      </section>

      {/* Challenge */}
      <section class="card settings-card">
        <h2 class="card-title">🧩 Challenge</h2>
        <div class="cf-grid">
          <NumberField label="Difficulty Normal" value={settings.difficultyNormal} min={1} max={10} onChange={(v) => set('difficultyNormal', v)} />
          <NumberField label="Difficulty Aggressive" value={settings.difficultyAggressive} min={1} max={10} onChange={(v) => set('difficultyAggressive', v)} />
          <NumberField label="Ban Normal (dk)" value={settings.banNormalMinutes} min={1} onChange={(v) => set('banNormalMinutes', v)} />
          <NumberField label="Ban Aggressive (dk)" value={settings.banAggressiveMinutes} min={1} onChange={(v) => set('banAggressiveMinutes', v)} />
        </div>
      </section>

      {/* Similarity */}
      <section class="card settings-card">
        <h2 class="card-title">🎯 Benzerlik Eşiği</h2>
        <div class="slider-row">
          <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>Normal</span>
          <input
            type="range"
            min={0.5}
            max={1}
            step={0.01}
            value={settings.threshold}
            aria-label="Benzerlik eşiği"
            onInput={(e) => set('threshold', Number((e.target as HTMLInputElement).value))}
          />
          <span class="slider-value">{settings.threshold.toFixed(2)}</span>
        </div>
        <div class="slider-row" style={{ marginTop: 12 }}>
          <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>Aggressive</span>
          <input
            type="range"
            min={0.5}
            max={1}
            step={0.01}
            value={settings.aggressiveThreshold}
            aria-label="Aggressive benzerlik eşiği"
            onInput={(e) => set('aggressiveThreshold', Number((e.target as HTMLInputElement).value))}
          />
          <span class="slider-value">{settings.aggressiveThreshold.toFixed(2)}</span>
        </div>
      </section>

      {/* Quota */}
      <section class="card settings-card">
        <h2 class="card-title">📊 Kota</h2>
        <Toggle checked={settings.unlimited} onChange={(v) => set('unlimited', v)} label="Sınırsız (kendi LXC)" />
        <div class="cf-grid" style={{ marginTop: 12 }}>
          <NumberField label="Günlük blok limiti" value={settings.dailyBlockQuota} min={0} step={1000} onChange={(v) => set('dailyBlockQuota', v)} />
          <NumberField label="Günlük challenge limiti" value={settings.dailyChallengeLimit} min={0} step={1000} onChange={(v) => set('dailyChallengeLimit', v)} />
        </div>
      </section>

      {/* Security toggles */}
      <section class="card settings-card">
        <h2 class="card-title">🔐 Güvenlik</h2>
        <div class="cf-toggles">
          <Toggle checked={settings.botFightMode} onChange={(v) => set('botFightMode', v)} label="Bot Fight Mode" />
          <Toggle checked={settings.browserIntegrityCheck} onChange={(v) => set('browserIntegrityCheck', v)} label="Browser Integrity Check" />
        </div>
        <div class="cf-grid" style={{ marginTop: 12 }}>
          <NumberField label="Challenge passage (dk)" value={settings.challengePassage} min={10} max={60} step={5} onChange={(v) => set('challengePassage', v)} />
        </div>
        <div style={{ marginTop: 12 }}>
          <div class="cf-field-label">Cache Level</div>
          <RadioGroup
            name="cache-level"
            value={settings.cacheLevel}
            options={CACHE_LEVELS}
            onChange={(v) => set('cacheLevel', v)}
          />
        </div>
        <div style={{ marginTop: 12 }}>
          <div class="cf-field-label">WAF Sensitivity</div>
          <RadioGroup
            name="waf-sensitivity"
            value={settings.wafSensitivity}
            options={WAF_SENSITIVITY}
            onChange={(v) => set('wafSensitivity', v)}
          />
        </div>
      </section>

      {/* Whitelist */}
      <section class="card settings-card">
        <h2 class="card-title">✅ IP Whitelist</h2>
        <div class="wl-row">
          <input
            class="auth-input"
            style={{ marginBottom: 0, flex: 1 }}
            placeholder="1.2.3.4 veya 192.168.0.0/16"
            value={whitelistInput}
            onInput={(e) => setWhitelistInput((e.target as HTMLInputElement).value)}
          />
          <button class="btn btn-accent" onClick={addWhitelist}>
            Ekle
          </button>
        </div>
        {settings.ipWhitelist.trim().length > 0 && (
          <div class="wl-list">
            {settings.ipWhitelist
              .split('\n')
              .map((l) => l.trim())
              .filter(Boolean)
              .map((ip) => (
                <div class="wl-item" key={ip}>
                  <span class="mono">{ip}</span>
                  <button class="btn btn-sm btn-danger" onClick={() => removeWhitelist(ip)}>
                    Kaldır
                  </button>
                </div>
              ))}
          </div>
        )}
      </section>

      {/* Geo blocker */}
      <section class="card settings-card">
        <h2 class="card-title">🌍 Geo Blocker</h2>
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

      {/* Manual ban */}
      <section class="card settings-card">
        <h2 class="card-title">🚫 Manuel Ban</h2>
        <div class="wl-row">
          <input
            class="auth-input"
            style={{ marginBottom: 0, flex: 1 }}
            placeholder="IP adresi"
            value={banIp}
            onInput={(e) => setBanIp((e.target as HTMLInputElement).value)}
          />
          <input
            class="auth-input"
            style={{ marginBottom: 0, flex: 1 }}
            placeholder="Sebep (opsiyonel)"
            value={banReason}
            onInput={(e) => setBanReason((e.target as HTMLInputElement).value)}
          />
          <button class="btn btn-danger" onClick={doBan}>
            Banla
          </button>
        </div>
        <button class="btn btn-sm" style={{ marginTop: 12 }} onClick={doClearBans}>
          Tüm banları temizle
        </button>
      </section>

      {/* Danger zone */}
      <section class="card settings-card danger-zone">
        <h2 class="card-title">☠️ Danger Zone</h2>
        <p class="card-desc">
          Kuralları varsayılana döndürmek için <code>RESET</code>, tam fabrika sıfırlaması için{' '}
          <code>FACTORY</code> yazın.
        </p>
        <div class="wl-row">
          <input
            class="auth-input"
            style={{ marginBottom: 0, flex: 1 }}
            placeholder="RESET veya FACTORY"
            value={confirmDanger}
            onInput={(e) => setConfirmDanger((e.target as HTMLInputElement).value.toUpperCase())}
          />
          <button class="btn btn-danger" onClick={doResetRules}>
            Kuralları Sıfırla
          </button>
          <button class="btn btn-danger" onClick={doFactoryReset}>
            Fabrika Sıfırla
          </button>
        </div>
      </section>

      {/* Deploy */}
      <section class="card settings-card">
        <h2 class="card-title">🚀 Deploy</h2>
        <p class="card-desc">
          Bu örneği özel buluta dağıt. Detaylar: <code>devmode/cloud/README.md</code>
        </p>
        <button class="btn btn-accent" onClick={doDeploy}>
          Deploy talimatlarını göster
        </button>
      </section>

      {/* Save */}
      <div class="save-bar">
        <button class="btn btn-accent btn-lg" onClick={() => void persist()}>
          💾 Tüm Ayarları Kaydet
        </button>
      </div>
    </div>
  );
}
