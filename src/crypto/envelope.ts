import type { KdfParams } from './types';

const MAGIC = new Uint8Array([0x54, 0x58, 0x43, 0x54]); // TXCT
const FIXED_HEADER_LENGTH = 28;
const ENVELOPE_VERSION = 1;
const KDF_SCRYPT = 1;
const CIPHER_AES_256_GCM = 1;

export const SALT_LENGTH = 16;
export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
export const DEFAULT_KDF_PARAMS: KdfParams = {
  N: 131_072,
  r: 8,
  p: 1,
};

export interface ParsedEnvelope {
  params: KdfParams;
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  additionalData: Uint8Array;
}

function validateParams(params: KdfParams): void {
  if (
    !Number.isInteger(params.N) ||
    params.N < 16_384 ||
    params.N > 1_048_576 ||
    (params.N & (params.N - 1)) !== 0
  ) {
    throw new Error('Invalid encrypted data');
  }
  if (!Number.isInteger(params.r) || params.r < 1 || params.r > 32) {
    throw new Error('Invalid encrypted data');
  }
  if (!Number.isInteger(params.p) || params.p < 1 || params.p > 4) {
    throw new Error('Invalid encrypted data');
  }
  const memoryBytes = 128 * params.r * (params.N + params.p + 1);
  if (!Number.isSafeInteger(memoryBytes) || memoryBytes > 256 * 1024 * 1024) {
    throw new Error('Invalid encrypted data');
  }
}

export function createAdditionalData(
  params: KdfParams,
  salt: Uint8Array,
  iv: Uint8Array,
  ciphertextLength: number,
): Uint8Array {
  validateParams(params);
  if (salt.length !== SALT_LENGTH || iv.length !== IV_LENGTH || ciphertextLength < 0) {
    throw new Error('Invalid encrypted data');
  }

  const bytes = new Uint8Array(FIXED_HEADER_LENGTH + salt.length + iv.length);
  const view = new DataView(bytes.buffer);
  bytes.set(MAGIC, 0);
  bytes[4] = ENVELOPE_VERSION;
  bytes[5] = KDF_SCRYPT;
  bytes[6] = CIPHER_AES_256_GCM;
  bytes[7] = 0;
  view.setUint32(8, params.N, false);
  view.setUint32(12, params.r, false);
  view.setUint32(16, params.p, false);
  bytes[20] = salt.length;
  bytes[21] = iv.length;
  bytes[22] = TAG_LENGTH;
  bytes[23] = 0;
  view.setUint32(24, ciphertextLength, false);
  bytes.set(salt, FIXED_HEADER_LENGTH);
  bytes.set(iv, FIXED_HEADER_LENGTH + salt.length);
  return bytes;
}

export function serializeEnvelope(
  additionalData: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): string {
  if (tag.length !== TAG_LENGTH) throw new Error('Invalid authentication tag');
  const bytes = new Uint8Array(additionalData.length + ciphertext.length + tag.length);
  bytes.set(additionalData);
  bytes.set(ciphertext, additionalData.length);
  bytes.set(tag, additionalData.length + ciphertext.length);
  return bytesToBase64(bytes);
}

export function parseEnvelope(value: string): ParsedEnvelope {
  const bytes = base64ToBytes(value.trim());
  if (bytes.length < FIXED_HEADER_LENGTH + SALT_LENGTH + IV_LENGTH + TAG_LENGTH) {
    throw new Error('Invalid encrypted data');
  }
  for (let index = 0; index < MAGIC.length; index += 1) {
    if (bytes[index] !== MAGIC[index]) throw new Error('Invalid encrypted data');
  }
  if (
    bytes[4] !== ENVELOPE_VERSION ||
    bytes[5] !== KDF_SCRYPT ||
    bytes[6] !== CIPHER_AES_256_GCM ||
    bytes[7] !== 0 ||
    bytes[20] !== SALT_LENGTH ||
    bytes[21] !== IV_LENGTH ||
    bytes[22] !== TAG_LENGTH ||
    bytes[23] !== 0
  ) {
    throw new Error('Invalid encrypted data');
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const params = {
    N: view.getUint32(8, false),
    r: view.getUint32(12, false),
    p: view.getUint32(16, false),
  };
  validateParams(params);
  const ciphertextLength = view.getUint32(24, false);
  const additionalDataLength = FIXED_HEADER_LENGTH + SALT_LENGTH + IV_LENGTH;
  const expectedLength = additionalDataLength + ciphertextLength + TAG_LENGTH;
  if (bytes.length !== expectedLength) throw new Error('Invalid encrypted data');

  const saltOffset = FIXED_HEADER_LENGTH;
  const ivOffset = saltOffset + SALT_LENGTH;
  const ciphertextOffset = ivOffset + IV_LENGTH;
  const tagOffset = ciphertextOffset + ciphertextLength;
  return {
    params,
    salt: bytes.slice(saltOffset, ivOffset),
    iv: bytes.slice(ivOffset, ciphertextOffset),
    ciphertext: bytes.slice(ciphertextOffset, tagOffset),
    tag: bytes.slice(tagOffset),
    additionalData: bytes.slice(0, ciphertextOffset),
  };
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  if (!value || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error('Invalid encrypted data');
  }
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error('Invalid encrypted data');
  }
}
