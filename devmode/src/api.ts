/**
 * fox-shield Developer Mode — API client.
 *
 * Every request carries the DEV_TOKEN as a Bearer header. The token is prompted
 * on first open and stored in localStorage. CORS is closed to localhost only.
 */

import type { DarkEntry, DevStats } from './types';

const TOKEN_KEY = 'fox-shield:dev-token';

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? '';
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(path, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
      authorization: `Bearer ${token}`,
      accept: 'application/json',
    },
  });
  if (res.status === 401) {
    throw new AuthError();
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

export function fetchDark(): Promise<DarkEntry[]> {
  return request<DarkEntry[]>('/api/dark');
}

export function fetchStats(): Promise<DevStats> {
  return request<DevStats>('/api/stats');
}

export function unban(ip: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>('/api/unban', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip }),
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
