import type { DeriveKey, KdfParams } from './types';

let sequence = 0;
const KDF_TIMEOUT_MS = 30_000;

export const deriveKeyInWorker: DeriveKey = (password, salt, params) =>
  new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./kdf.worker.ts', import.meta.url), { type: 'module' });
    const id = sequence++;
    const passwordCopy = password.slice();
    const saltCopy = salt.slice();
    const timeout = window.setTimeout(() => {
      worker.terminate();
      reject(new Error('Key derivation timed out'));
    }, KDF_TIMEOUT_MS);

    worker.onmessage = ({ data }: MessageEvent<{ id: number; key?: Uint8Array; error?: string }>) => {
      if (data.id !== id) return;
      window.clearTimeout(timeout);
      worker.terminate();
      if (data.key) resolve(data.key);
      else reject(new Error(data.error ?? 'Key derivation failed'));
    };
    worker.onerror = () => {
      window.clearTimeout(timeout);
      worker.terminate();
      reject(new Error('Key derivation failed'));
    };
    worker.postMessage(
      { id, password: passwordCopy, salt: saltCopy, params } satisfies {
        id: number;
        password: Uint8Array;
        salt: Uint8Array;
        params: KdfParams;
      },
      [passwordCopy.buffer, saltCopy.buffer],
    );
  });
