/// <reference lib="webworker" />
import { argon2id } from '@noble/hashes/argon2.js';
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
    const key = argon2id(password, salt, {
      t: params.iterations,
      m: params.memory,
      p: params.parallelism,
      dkLen: 32,
      maxmem: 256 * 1024 * 1024,
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
