import { useState } from 'preact/hooks';
import type { DarkEntry } from '../types';

interface DarkListProps {
  entries: DarkEntry[];
  onUnban: (ip: string) => void;
  onDelete: (hash: string) => void;
}

function formatTime(ms: number): string {
  return new Date(ms).toLocaleString('tr-TR', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function DarkList({ entries, onUnban, onDelete }: DarkListProps) {
  const [copied, setCopied] = useState('');

  const copyHash = async (hash: string) => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(hash);
      window.setTimeout(() => setCopied(''), 1500);
    } catch {
      // Clipboard unavailable — ignore.
    }
  };

  return (
    <div class="card">
      <h2 class="card-title">Dark List · {entries.length} kayıt</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Hash</th>
              <th>IP</th>
              <th>Reason</th>
              <th>Zaman</th>
              <th>İstek örneği</th>
              <th>Durum</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.hash}>
                <td>
                  <span class="hash" title="Kopyala" onClick={() => void copyHash(e.hash)}>
                    {e.hash}
                  </span>
                  {copied === e.hash && <span style={{ color: 'var(--ok)', fontSize: 11 }}> ✓</span>}
                </td>
                <td class="mono">{e.ip}</td>
                <td>
                  <span class={`reason ${e.destroyed ? 'destroy' : ''}`}>{e.reason}</span>
                </td>
                <td class="mono">{formatTime(e.timestamp)}</td>
                <td>
                  <div class="sample">
                    <span class="method">{e.sample.method}</span> {e.sample.url}
                  </div>
                </td>
                <td>
                  {e.destroyed ? (
                    <span class="badge destroyed">Destroyed</span>
                  ) : e.banned ? (
                    <span class="badge banned">Banlı</span>
                  ) : (
                    <span class="badge active">Aktif</span>
                  )}
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {e.banned && (
                      <button class="btn btn-sm" onClick={() => onUnban(e.ip)}>
                        Unban
                      </button>
                    )}
                    <button class="btn btn-sm btn-danger" onClick={() => onDelete(e.hash)}>
                      Sil
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
