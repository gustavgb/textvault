import { scrypt } from '@noble/hashes/scrypt.js';
import { KDF_MAX_MEMORY_BYTES } from './envelope';
import type { DeriveKey } from './types';

export const deriveScryptKey: DeriveKey = async (password, salt, params) =>
  scrypt(password, salt, {
    N: params.N,
    r: params.r,
    p: params.p,
    dkLen: 32,
    maxmem: KDF_MAX_MEMORY_BYTES,
  });
