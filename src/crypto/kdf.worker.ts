/// <reference lib="webworker" />
import { deriveScryptKey } from './scrypt';
import type { KdfParams } from './types';

interface DeriveRequest {
  id: number;
  password: Uint8Array;
  salt: Uint8Array;
  params: KdfParams;
}

self.onmessage = async ({ data }: MessageEvent<DeriveRequest>) => {
  const { id, password, salt, params } = data;
  try {
    const key = await deriveScryptKey(password, salt, params);
    self.postMessage({ id, key }, { transfer: [key.buffer] });
  } catch {
    self.postMessage({ id, error: 'Key derivation failed' });
  } finally {
    password.fill(0);
    salt.fill(0);
  }
};

export {};
