import { useState } from 'preact/hooks';
import { setToken } from '../api';

interface AuthGateProps {
  onAuthed: () => void;
}

export function AuthGate({ onAuthed }: AuthGateProps) {
  const [token, setTokenValue] = useState('');
  const [error, setError] = useState('');

  const submit = (e: Event) => {
    e.preventDefault();
    if (token.trim().length === 0) {
      setError('Token boş olamaz.');
      return;
    }
    setToken(token.trim());
    onAuthed();
  };

  return (
    <div class="auth">
      <form class="auth-card" onSubmit={submit}>
        <h1>Developer Mode</h1>
        <p>
          Bu görünüm yalnızca sahibine özeldir. Devam etmek için <code>DEV_TOKEN</code> girin.
        </p>
        <input
          class="auth-input"
          type="password"
          placeholder="DEV_TOKEN"
          value={token}
          onInput={(e) => setTokenValue((e.target as HTMLInputElement).value)}
          autoFocus
        />
        {error && <p class="auth-error">{error}</p>}
        <button class="btn btn-accent" type="submit" style={{ width: '100%' }}>
          Giriş
        </button>
      </form>
    </div>
  );
}
