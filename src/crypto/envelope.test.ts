import { describe, expect, it } from 'vitest';
import {
  createAdditionalData,
  DEFAULT_KDF_PARAMS,
  MAX_PLAINTEXT_BYTES,
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
    expect(parsed.params).toEqual({ N: 131_072, r: 8, p: 1 });
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

  it('rejects envelopes above the ciphertext size limit before decoding', () => {
    const maximumEnvelopeBytes = 28 + 16 + 12 + MAX_PLAINTEXT_BYTES + 16;
    const oversizedBase64 = 'A'.repeat(4 * Math.ceil(maximumEnvelopeBytes / 3) + 4);
    expect(() => parseEnvelope(oversizedBase64)).toThrow('Invalid encrypted data');
  });

  it('rejects KDF parameters above the supported work limit', () => {
    const aad = createAdditionalData(DEFAULT_KDF_PARAMS, new Uint8Array(16), new Uint8Array(12), 0);
    const blob = serializeEnvelope(aad, new Uint8Array(), new Uint8Array(16));
    const raw = Uint8Array.from(atob(blob), (character) => character.charCodeAt(0));
    new DataView(raw.buffer).setUint32(16, 2, false);
    const modified = btoa(String.fromCharCode(...raw));
    expect(() => parseEnvelope(modified)).toThrow('Invalid encrypted data');
  });
});
