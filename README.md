# Text Vault

A browser-only text encryption app using AES-256-GCM and scrypt. The application does not transmit or intentionally persist passwords, keys, plaintext, or ciphertext. Values remain in the page's memory until cleared or the page is closed.

## Development

```sh
pnpm install
pnpm dev
```

Run checks with `pnpm test` and `pnpm build`.

The encrypted output is a versioned binary envelope encoded as one standard base64 string. It includes the KDF parameters, salt, IV, ciphertext, and authentication tag required for future decryption.

## Deployment security

Deploy only over HTTPS and configure the response headers listed in `public/_headers`. That file is consumed automatically by hosts that support the `_headers` convention; other hosts must be configured with equivalent headers. Verify the headers on the deployed URL before publishing the application.
