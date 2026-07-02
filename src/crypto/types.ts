export interface KdfParams {
  memory: number;
  iterations: number;
  parallelism: number;
}

export type DeriveKey = (
  password: Uint8Array,
  salt: Uint8Array,
  params: KdfParams,
) => Promise<Uint8Array>;
