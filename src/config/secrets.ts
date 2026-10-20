import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

export interface SecretReference {
  /** Opaque pointer to the managed secret store (KMS/secret manager). */
  provider: string;
  /** Key/ARN/path identifying the secret in the managed store. */
  keyId: string;
  /** Optional version for rotation tracking. */
  version?: string;
}

export interface EncryptedSecret {
  /** Ciphertext (base64) — never plaintext. */
  ciphertext: string;
  /** Initialization vector (base64). */
  iv: string;
  /** Auth tag (base64) for AES-256-GCM. */
  authTag: string;
  /** Key identifier used for encryption, for rotation. */
  keyId: string;
}

/**
 * A channel-account signing secret is persisted ONLY as a reference to the
 * managed secret store or as an encrypted value. Plaintext secrets must never
 * be written to the channel account model.
 */
export type ChannelAccountSecret = { kind: 'reference'; ref: SecretReference } | { kind: 'encrypted'; value: EncryptedSecret };

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

export interface SecretStoreConfig {
  /** Provider name, e.g. "aws-kms", "gcp-secret-manager", "vault". */
  provider: string;
  /** Base64-encoded 32-byte data-encryption key material (from KMS). */
  dataKey?: string;
  /** Salt used to derive the encryption key from dataKey. */
  salt?: string;
}

function deriveKey(config: SecretStoreConfig): Buffer {
  if (!config.dataKey) {
    throw new Error('Secret store data key is not configured');
  }
  const raw = Buffer.from(config.dataKey, 'base64');
  if (raw.length < 32) {
    throw new Error('Secret store data key must be at least 32 bytes');
  }
  const salt = config.salt ? Buffer.from(config.salt, 'base64') : Buffer.alloc(0);
  return scryptSync(raw, salt, 32);
}

/**
 * Encrypt a channel-account signing secret for at-rest persistence. The
 * returned value contains no plaintext and can be stored on the model.
 */
export function encryptChannelSecret(plaintext: string, config: SecretStoreConfig): EncryptedSecret {
  const key = deriveKey(config);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    keyId: config.provider,
  };
}

/**
 * Decrypt a previously encrypted channel-account signing secret. Only call
 * this at signing time; never log or persist the result.
 */
export function decryptChannelSecret(value: EncryptedSecret, config: SecretStoreConfig): string {
  const key = deriveKey(config);
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(value.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(value.authTag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(value.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

/**
 * Build a reference to a secret held in the managed secret store. Prefer this
 * over persisting encrypted values when the store supports direct retrieval.
 */
export function secretReference(provider: string, keyId: string, version?: string): SecretReference {
  return { provider, keyId, version };
}

/**
 * Resolve a channel-account secret to plaintext for signing. References are
 * resolved through the injected managed-store fetcher; encrypted values are
 * decrypted locally. Plaintext is returned transiently and never persisted.
 */
export async function resolveChannelSecret(
  secret: ChannelAccountSecret,
  config: SecretStoreConfig,
  fetchFromStore: (ref: SecretReference) => Promise<string>,
): Promise<string> {
  if (secret.kind === 'reference') {
    return fetchFromStore(secret.ref);
  }
  return decryptChannelSecret(secret.value, config);
}

/**
 * Guard that rejects any attempt to persist a plaintext signing secret on a
 * channel account. Call before writing the channel account model.
 */
export function assertNoPlaintextSecret(secret: unknown): void {
  if (typeof secret === 'string' && secret.length > 0) {
    throw new Error('Refusing to persist plaintext channel-account secret; use a reference or encrypted value');
  }
}
