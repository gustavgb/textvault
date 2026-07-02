export interface KdfParams {
  N: number;
  r: number;
  p: number;
}

export type DeriveKey = (
  password: Uint8Array,
  salt: Uint8Array,
  params: KdfParams,
) => Promise<Uint8Array>;
