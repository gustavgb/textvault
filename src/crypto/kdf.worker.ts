/// <reference lib="webworker" />
import { scrypt } from '@noble/hashes/scrypt.js';
import type { KdfParams } from './types';

interface DeriveRequest {
  id: number;
  password: Uint8Array;
  salt: Uint8Array;
  params: KdfParams;
}

self.onmessage = ({ data }: MessageEvent<DeriveRequest>) => {
  const { id, password, salt, params } = data;
  try {
    const key = scrypt(password, salt, {
      N: params.N,
      r: params.r,
      p: params.p,
      dkLen: 32,
      maxmem: 129 * 1024 * 1024,
    });
    self.postMessage({ id, key }, { transfer: [key.buffer] });
  } catch {
    self.postMessage({ id, error: 'Key derivation failed' });
  } finally {
    password.fill(0);
    salt.fill(0);
  }
};

export {};
