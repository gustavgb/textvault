# Text Vault

A browser-only text encryption app using AES-256-GCM and Argon2id. Passwords, keys, plaintext, and ciphertext never leave the browser and are not persisted.

## Development

```sh
pnpm install
pnpm dev
```

Run checks with `pnpm test` and `pnpm build`.

The encrypted output is a versioned binary envelope encoded as one standard base64 string. It includes the KDF parameters, salt, IV, ciphertext, and authentication tag required for future decryption.
