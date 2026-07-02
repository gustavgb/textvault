import { describe, expect, it } from 'vitest';
import {
  createAdditionalData,
  DEFAULT_KDF_PARAMS,
  parseEnvelope,
  serializeEnvelope,
} from './envelope';

describe('encrypted envelope', () => {
  it('round-trips all fields', () => {
    const salt = new Uint8Array(16).fill(7);
    const iv = new Uint8Array(12).fill(9);
    const ciphertext = new Uint8Array([1, 2, 3]);
    const tag = new Uint8Array(16).fill(11);
    const aad = createAdditionalData(DEFAULT_KDF_PARAMS, salt, iv, ciphertext.length);
    const parsed = parseEnvelope(serializeEnvelope(aad, ciphertext, tag));

    expect(parsed.params).toEqual(DEFAULT_KDF_PARAMS);
    expect(parsed.salt).toEqual(salt);
    expect(parsed.iv).toEqual(iv);
    expect(parsed.ciphertext).toEqual(ciphertext);
    expect(parsed.tag).toEqual(tag);
    expect(parsed.params.memory).toBe(65_536);
  });

  it('continues to parse envelopes using the previous 128 MiB KDF cost', () => {
    const previousParams = { memory: 131_072, iterations: 3, parallelism: 1 };
    const aad = createAdditionalData(previousParams, new Uint8Array(16), new Uint8Array(12), 0);
    const parsed = parseEnvelope(serializeEnvelope(aad, new Uint8Array(), new Uint8Array(16)));
    expect(parsed.params).toEqual(previousParams);
  });

  it.each(['', 'not base64', 'AAAA', 'VFhDVAEBARMAAgAAA'])('rejects malformed input', (value) => {
    expect(() => parseEnvelope(value)).toThrow('Invalid encrypted data');
  });

  it('rejects inconsistent lengths and unsupported versions', () => {
    const aad = createAdditionalData(DEFAULT_KDF_PARAMS, new Uint8Array(16), new Uint8Array(12), 1);
    const blob = serializeEnvelope(aad, new Uint8Array([1]), new Uint8Array(16));
    const raw = Uint8Array.from(atob(blob), (character) => character.charCodeAt(0));
    raw[4] = 2;
    const modified = btoa(String.fromCharCode(...raw));
    expect(() => parseEnvelope(modified)).toThrow('Invalid encrypted data');
  });
});
