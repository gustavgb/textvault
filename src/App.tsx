import { useEffect, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { decryptText, encryptText } from './crypto/crypt';
import './styles.css';

type Action = 'encrypt' | 'decrypt';

export default function App() {
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<Action | null>(null);
  const [copied, setCopied] = useState(false);
  const [outputAction, setOutputAction] = useState<Action | null>(null);
  const [pendingAction, setPendingAction] = useState<Action | null>(null);
  const passwordInputRef = useRef<HTMLInputElement>(null);
  const modalRef = useRef<HTMLElement>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (pendingAction) passwordInputRef.current?.focus();
  }, [pendingAction]);

  function openPasswordPrompt(action: Action, trigger: HTMLButtonElement) {
    setError('');
    if (action === 'decrypt' && !input) {
      setError('Paste encrypted text to decrypt.');
      return;
    }
    triggerRef.current = trigger;
    setPassword('');
    setConfirmation('');
    setPendingAction(action);
  }

  function closePasswordPrompt() {
    if (busy) return;
    setPendingAction(null);
    setPassword('');
    setConfirmation('');
    window.setTimeout(() => triggerRef.current?.focus(), 0);
  }

  function handleModalKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape') {
      closePasswordPrompt();
      return;
    }
    if (event.key !== 'Tab') return;

    const focusable = Array.from(
      modalRef.current?.querySelectorAll<HTMLElement>('input:not(:disabled), button:not(:disabled)') ?? [],
    );
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  async function run() {
    if (!pendingAction) return;
    const action = pendingAction;
    setError('');
    setOutput('');
    setOutputAction(null);
    setCopied(false);

    if (!password) {
      setError('Enter a password.');
      return;
    }
    if (!input && action === 'decrypt') {
      setError('Paste encrypted text to decrypt.');
      return;
    }
    if (action === 'encrypt') {
      if (password.length < 12) {
        setError('Use a password with at least 12 characters.');
        return;
      }
      if (password !== confirmation) {
        setError('The passwords do not match.');
        return;
      }
    }

    setBusy(action);
    try {
      const result = action === 'encrypt'
        ? await encryptText(input, password)
        : await decryptText(input, password);
      setOutput(result);
      setOutputAction(action);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Something went wrong.');
    } finally {
      setBusy(null);
      setPendingAction(null);
      setPassword('');
      setConfirmation('');
      window.setTimeout(() => triggerRef.current?.focus(), 0);
    }
  }

  async function copyOutput() {
    try {
      await navigator.clipboard.writeText(output);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setError('Clipboard access was denied by the browser.');
    }
  }

  function clearAll() {
    setInput('');
    setOutput('');
    setOutputAction(null);
    setPassword('');
    setConfirmation('');
    setError('');
    setCopied(false);
  }

  return (
    <main className="page-shell">
      <div className="content-column">
        <section className="app-card" aria-labelledby="page-title">
        <header>
          <img className="mark" src="/text-vault-logo.svg" alt="" />
          <div>
            <h1 id="page-title">Text Vault</h1>
            <p>Private encryption, entirely in your browser.</p>
          </div>
        </header>

        <div className="privacy-note">
          <span aria-hidden="true">●</span>
          Nothing is transmitted or intentionally stored by this app.
        </div>

        <label>
          <span>Text or encrypted blob</span>
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            disabled={busy !== null}
            placeholder="Type text to encrypt, or paste a blob to decrypt…"
            rows={8}
          />
        </label>

        <div className="actions">
          <button className="primary" onClick={(event) => openPasswordPrompt('encrypt', event.currentTarget)} disabled={busy !== null}>
            {busy === 'encrypt' ? 'Deriving key…' : 'Encrypt'}
          </button>
          <button onClick={(event) => openPasswordPrompt('decrypt', event.currentTarget)} disabled={busy !== null}>
            {busy === 'decrypt' ? 'Deriving key…' : 'Decrypt'}
          </button>
          <button onClick={clearAll} disabled={busy !== null || (!input && !output)}>
            Clear all
          </button>
        </div>

        <div className="message-space" aria-live="polite">
          {error && <p className="error" role="alert">{error}</p>}
          {busy && <p className="status">scrypt is running securely in a background worker.</p>}
        </div>

        <div className="output-heading">
          <span>Output</span>
          {output && <button className="copy" onClick={() => void copyOutput()}>{copied ? 'Copied' : 'Copy'}</button>}
        </div>
        <output className={output ? 'output has-value' : 'output'}>
          {output || 'Your result will appear here.'}
        </output>
        {output && outputAction === 'decrypt' && (
          <p className="clipboard-warning">Copying plaintext may leave it in clipboard history managed by your browser or operating system.</p>
        )}

        <footer>
          AES-256-GCM · scrypt ·{' '}
          <a href="https://github.com/gustavgb/textvault" target="_blank" rel="noreferrer">
            View on GitHub
          </a>
        </footer>
        </section>

        <article className="security-info" aria-labelledby="security-title">
          <h2 id="security-title">How your text is protected</h2>
          <p>
            Text Vault performs every operation locally in this browser. Your text, password, and encryption key are
            are not transmitted or intentionally written to browser storage. Values remain in this page's memory until
            you clear them or close the page; JavaScript strings cannot be reliably erased from browser memory.
          </p>

          <h3>From password to encryption key</h3>
          <p>
            Your password is converted into a 256-bit key with scrypt, a memory-hard password derivation function.
            Each new encryption uses a cryptographically random salt and runs scrypt with a work factor of 131,072,
            a block size of 8, and one parallel lane, requiring approximately 128 MiB of memory. This deliberately
            makes password guessing expensive. The derivation runs in a background worker so the page remains responsive.
          </p>

          <h3>Authenticated encryption</h3>
          <p>
            The derived key encrypts the UTF-8 text with AES-256-GCM. A fresh random IV is generated for every
            encryption. GCM also produces an authentication tag, which detects a wrong password or any modification
            to the ciphertext and its protected metadata instead of returning corrupted text.
          </p>

          <h3>What the base64 output contains</h3>
          <p>
            The output is one versioned binary envelope encoded as base64. It contains the salt, scrypt parameters,
            IV, ciphertext, and GCM authentication tag. None of these values reveals the password or plaintext. The
            stored parameters allow this app to decrypt older envelopes if the default KDF cost changes later.
          </p>

          <aside className="password-warning">
            <strong>Your password cannot be recovered or reset.</strong>
            <p>
              There is no account, recovery key, or copy of your password. If you lose it, the encrypted text is
              permanently inaccessible. Store it in a trusted password manager and use a long, unique password.
            </p>
          </aside>

          <p className="security-limit">
            Encryption protects the saved blob, but it cannot protect text on a compromised device or browser. Its
            resistance to password guessing also depends on the strength and uniqueness of the password you choose.
          </p>
        </article>
      </div>

      {pendingAction && (
        <div
          className="modal-backdrop"
          onMouseDown={(event) => event.target === event.currentTarget && closePasswordPrompt()}
          onKeyDown={handleModalKeyDown}
        >
          <section ref={modalRef} className="password-modal" role="dialog" aria-modal="true" aria-labelledby="password-title">
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void run();
              }}
            >
              <h2 id="password-title">{pendingAction === 'encrypt' ? 'Encrypt this text' : 'Decrypt this text'}</h2>
              <p>
                {pendingAction === 'encrypt'
                  ? 'Choose a password you can safely retain. It cannot be recovered.'
                  : 'Enter the password used when this text was encrypted.'}
              </p>
              <label>
                <span>Password</span>
                <input
                  ref={passwordInputRef}
                  type="password"
                  autoComplete={pendingAction === 'encrypt' ? 'new-password' : 'current-password'}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={busy !== null}
                  placeholder={pendingAction === 'encrypt' ? 'At least 12 characters' : 'Enter password'}
                />
              </label>
              {pendingAction === 'encrypt' && (
                <label>
                  <span>Confirm password</span>
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                    disabled={busy !== null}
                    placeholder="Repeat your password"
                  />
                </label>
              )}
              {error && <p className="modal-error" role="alert">{error}</p>}
              {busy && <p className="status">scrypt is running securely in a background worker.</p>}
              <div className="modal-actions">
                <button type="button" onClick={closePasswordPrompt} disabled={busy !== null}>Cancel</button>
                <button type="submit" className="primary" disabled={busy !== null}>
                  {busy ? 'Deriving key…' : pendingAction === 'encrypt' ? 'Encrypt' : 'Decrypt'}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </main>
  );
}
