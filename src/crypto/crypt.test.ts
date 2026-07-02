import { describe, expect, it } from 'vitest';
import { decryptText, encryptText } from './crypt';
import type { DeriveKey } from './types';

const quickDerive: DeriveKey = async (password, salt) => {
  const material = new Uint8Array(password.length + salt.length);
  material.set(password);
  material.set(salt, password.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', material));
};

describe('text encryption', () => {
  it.each(['', 'plain text', 'Unicode: æøå 🔐\nsecond line'])('round-trips %j', async (plaintext) => {
    const encrypted = await encryptText(plaintext, 'correct horse battery', quickDerive);
    await expect(decryptText(encrypted, 'correct horse battery', quickDerive)).resolves.toBe(plaintext);
  });

  it('uses fresh random values', async () => {
    const first = await encryptText('same', 'correct horse battery', quickDerive);
    const second = await encryptText('same', 'correct horse battery', quickDerive);
    expect(first).not.toBe(second);
  });

  it('rejects a wrong password and tampering', async () => {
    const encrypted = await encryptText('secret', 'correct horse battery', quickDerive);
    await expect(decryptText(encrypted, 'incorrect password', quickDerive)).rejects.toThrow('Unable to decrypt');
    const raw = Uint8Array.from(atob(encrypted), (character) => character.charCodeAt(0));
    raw[raw.length - 17] ^= 1;
    const tampered = btoa(String.fromCharCode(...raw));
    await expect(decryptText(tampered, 'correct horse battery', quickDerive)).rejects.toThrow('Unable to decrypt');
  });
});
