import { describe, expect, it } from 'vitest';
import { DEFAULT_KDF_PARAMS } from './envelope';
import { deriveScryptKey } from './scrypt';

describe('production scrypt configuration', () => {
  it('derives a 256-bit key with the default parameters', async () => {
    const password = new TextEncoder().encode('correct horse battery');
    const salt = new Uint8Array(16).fill(7);
    const key = await deriveScryptKey(password, salt, DEFAULT_KDF_PARAMS);

    expect(key).toHaveLength(32);
    expect(key).toEqual(await deriveScryptKey(password, salt, DEFAULT_KDF_PARAMS));
    key.fill(0);
    password.fill(0);
    salt.fill(0);
  }, 10_000);
});
