/**
 * fox-shield Developer Mode — API client.
 *
 * Every request carries the DEV_TOKEN as a Bearer header and the device
 * fingerprint as an X-Device-Id header. The token is prompted on first open and
 * stored in localStorage; the device id is generated once and persisted.
 */

import type { DarkEntry, DevStats, ShieldSettings, SystemInfo } from './types';

const TOKEN_KEY = 'fox-shield:dev-token';
const DEVICE_KEY = 'fox-shield:device-id';

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? '';
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

/** Generate a stable device fingerprint for this browser/PC. */
function generateDeviceId(): string {
  const parts = [
    navigator.userAgent,
    navigator.language,
    screen.width,
    screen.height,
    screen.colorDepth,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
  ];
  let hash = 0;
  const seed = parts.join('|');
  for (let i = 0; i < seed.length; i += 1) {
    hash = (hash << 5) - hash + seed.charCodeAt(i);
    hash |= 0;
  }
  return `dev-${Math.abs(hash).toString(16).padStart(8, '0')}`;
}

/** Get (and lazily create) the persisted device id. */
export function getDeviceId(): string {
  let id = localStorage.getItem(DEVICE_KEY);
  if (!id) {
    id = generateDeviceId();
    localStorage.setItem(DEVICE_KEY, id);
  }
  return id;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(path, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
      authorization: `Bearer ${token}`,
      'x-device-id': getDeviceId(),
      accept: 'application/json',
    },
  });
  if (res.status === 401) {
    throw new AuthError();
  }
  if (res.status === 403) {
    throw new DeviceError();
  }
  if (!res.ok) {
    throw new Error(`Request failed: ${res.status}`);
  }
  return (await res.json()) as T;
}

export class AuthError extends Error {
  constructor() {
    super('unauthorized');
    this.name = 'AuthError';
  }
}

export class DeviceError extends Error {
  constructor() {
    super('device not bound');
    this.name = 'DeviceError';
  }
}

export function fetchDark(): Promise<DarkEntry[]> {
  return request<DarkEntry[]>('/api/dark');
}

export function fetchStats(): Promise<DevStats> {
  return request<DevStats>('/api/stats');
}

export function fetchSettings(): Promise<ShieldSettings> {
  return request<ShieldSettings>('/api/settings');
}

export function fetchSystem(): Promise<SystemInfo> {
  return request<SystemInfo>('/api/system');
}

export function saveSettings(settings: ShieldSettings): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/settings', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(settings),
  });
}

export function unban(ip: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/unban', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip }),
  });
}

export function ban(ip: string, reason: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/ban', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip, reason }),
  });
}

export function clearBans(): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/clear-bans', { method: 'POST' });
}

export function whitelist(ip: string, action: 'add' | 'remove'): Promise<{ ok: boolean; whitelist: string[] }> {
  return request<{ ok: boolean; whitelist: string[] }>('/api/whitelist', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip, action }),
  });
}

export function setGeo(countries: string[]): Promise<{ ok: boolean; blocked: string[] }> {
  return request<{ ok: boolean; blocked: string[] }>('/api/geo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ countries }),
  });
}

export function deleteDark(hash: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/dark/delete', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ hash }),
  });
}

export function setThreshold(threshold: number): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/threshold', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ threshold }),
  });
}

export function setMode(aggressive: boolean): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/mode', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ aggressive }),
  });
}

export function resetRules(): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/reset-rules', { method: 'POST' });
}

export function factoryReset(): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/factory-reset', { method: 'POST' });
}

export function deploy(): Promise<{ ok: boolean; mode: string; instructions: string }> {
  return request<{ ok: boolean; mode: string; instructions: string }>('/api/deploy', { method: 'POST' });
}
