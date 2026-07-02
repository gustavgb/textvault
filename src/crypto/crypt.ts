import {
  createAdditionalData,
  DEFAULT_KDF_PARAMS,
  IV_LENGTH,
  parseEnvelope,
  SALT_LENGTH,
  serializeEnvelope,
  TAG_LENGTH,
} from './envelope';
import { deriveKeyInWorker } from './kdf';
import type { DeriveKey } from './types';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

async function deriveAndClearPassword(
  password: string,
  salt: Uint8Array,
  deriveKey: DeriveKey,
  params = DEFAULT_KDF_PARAMS,
): Promise<Uint8Array> {
  const passwordBytes = encoder.encode(password);
  try {
    return await deriveKey(passwordBytes, salt, params);
  } finally {
    passwordBytes.fill(0);
  }
}

export async function encryptText(
  plaintext: string,
  password: string,
  deriveKey: DeriveKey = deriveKeyInWorker,
): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const plaintextBytes = encoder.encode(plaintext);
  const additionalData = createAdditionalData(DEFAULT_KDF_PARAMS, salt, iv, plaintextBytes.length);
  let rawKey: Uint8Array | undefined;
  try {
    rawKey = await deriveAndClearPassword(password, salt, deriveKey);
    const key = await crypto.subtle.importKey('raw', toArrayBuffer(rawKey), 'AES-GCM', false, ['encrypt']);
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: toArrayBuffer(iv),
          additionalData: toArrayBuffer(additionalData),
          tagLength: TAG_LENGTH * 8,
        },
        key,
        toArrayBuffer(plaintextBytes),
      ),
    );
    const tagOffset = encrypted.length - TAG_LENGTH;
    return serializeEnvelope(additionalData, encrypted.slice(0, tagOffset), encrypted.slice(tagOffset));
  } finally {
    rawKey?.fill(0);
    plaintextBytes.fill(0);
  }
}

export async function decryptText(
  envelope: string,
  password: string,
  deriveKey: DeriveKey = deriveKeyInWorker,
): Promise<string> {
  try {
    const parsed = parseEnvelope(envelope);
    const rawKey = await deriveAndClearPassword(password, parsed.salt, deriveKey, parsed.params);
    try {
      const key = await crypto.subtle.importKey('raw', toArrayBuffer(rawKey), 'AES-GCM', false, ['decrypt']);
      const encrypted = new Uint8Array(parsed.ciphertext.length + parsed.tag.length);
      encrypted.set(parsed.ciphertext);
      encrypted.set(parsed.tag, parsed.ciphertext.length);
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: toArrayBuffer(parsed.iv),
          additionalData: toArrayBuffer(parsed.additionalData),
          tagLength: TAG_LENGTH * 8,
        },
        key,
        toArrayBuffer(encrypted),
      );
      return decoder.decode(plaintext);
    } finally {
      rawKey.fill(0);
    }
  } catch {
    throw new Error('Unable to decrypt. Check the password and encrypted text.');
  }
}
