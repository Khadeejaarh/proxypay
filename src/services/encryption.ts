import crypto from 'crypto';

/**
 * Versioned PII encryption with resumable key rotation.
 *
 * Ciphertext is stored as `v<version>:<iv>:<tag>:<payload>` so the key version
 * used to encrypt a value is identifiable at read time. This allows reads to
 * keep working during a mixed-key rollout (and rollback) while a batch job
 * migrates records from an old key version to a new one.
 */

export interface KeyRing {
  /** Currently active key version used for new encryptions. */
  activeVersion: number;
  /** Map of key version -> raw key material (Buffer or base64 string). */
  keys: Record<number, Buffer | string>;
}

export interface EncryptedValue {
  version: number;
  ciphertext: string;
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const PREFIX = 'v';

function toKeyBuffer(key: Buffer | string): Buffer {
  const buf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'base64');
  if (buf.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (AES-256)');
  }
  return buf;
}

function resolveKey(keyRing: KeyRing, version: number): Buffer {
  const key = keyRing.keys[version];
  if (!key) {
    throw new Error(`No key material for encryption version ${version}`);
  }
  return toKeyBuffer(key);
}

/**
 * Encrypt a plaintext value using the active key version.
 * Returns a self-describing string that records the key version.
 */
export function encrypt(plaintext: string, keyRing: KeyRing): string {
  const version = keyRing.activeVersion;
  const key = resolveKey(keyRing, version);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const payload = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    `${PREFIX}${version}`,
    iv.toString('base64'),
    tag.toString('base64'),
    payload.toString('base64'),
  ].join(':');
}

/**
 * Parse the key version recorded in a ciphertext string.
 */
export function getKeyVersion(ciphertext: string): number {
  const parts = ciphertext.split(':');
  if (parts.length !== 4 || !parts[0].startsWith(PREFIX)) {
    throw new Error('Malformed ciphertext: missing key version metadata');
  }
  const version = Number.parseInt(parts[0].slice(PREFIX.length), 10);
  if (!Number.isInteger(version)) {
    throw new Error('Malformed ciphertext: invalid key version');
  }
  return version;
}

/**
 * Decrypt a value using the key version recorded in the ciphertext.
 * This keeps reads working during mixed-key rollout and rollback.
 */
export function decrypt(ciphertext: string, keyRing: KeyRing): string {
  const version = getKeyVersion(ciphertext);
  const key = resolveKey(keyRing, version);
  const [, ivB64, tagB64, payloadB64] = ciphertext.split(':');
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const payload = Buffer.from(payloadB64, 'base64');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(payload), decipher.final()]).toString('utf8');
}

/**
 * Re-encrypt a single value to the active key version, verifying the result
 * before returning it. Returns the original ciphertext unchanged if it is
 * already on the active version.
 */
export function reencrypt(ciphertext: string, keyRing: KeyRing): string {
  const currentVersion = getKeyVersion(ciphertext);
  if (currentVersion === keyRing.activeVersion) {
    return ciphertext;
  }
  const plaintext = decrypt(ciphertext, keyRing);
  const migrated = encrypt(plaintext, keyRing);
  // Verify the migrated value round-trips before it is committed.
  const verified = decrypt(migrated, keyRing);
  if (verified !== plaintext) {
    throw new Error('Re-encryption verification failed: plaintext mismatch');
  }
  return migrated;
}

export interface RotationRecord {
  id: string;
  ciphertext: string;
}

export interface RotationStore {
  /** Fetch a page of records still on the given (old) key version. */
  fetchBatch(fromVersion: number, cursor: string | undefined, limit: number): Promise<RotationRecord[]>;
  /** Persist a re-encrypted value for a record. */
  update(id: string, ciphertext: string): Promise<void>;
}

export interface RotationOptions {
  batchSize?: number;
  /** Resume from a previously persisted cursor. */
  cursor?: string;
  /** Called after each committed batch so progress can be persisted. */
  onProgress?: (cursor: string | undefined, migrated: number) => Promise<void> | void;
}

export interface RotationResult {
  migrated: number;
  cursor: string | undefined;
  done: boolean;
}

/**
 * Resumable batch re-encryption from an old key version to the active one.
 * Each record is verified before being committed, and progress is reported
 * per batch so an interrupted run can resume from the last cursor.
 */
export async function rotateKeys(
  store: RotationStore,
  keyRing: KeyRing,
  fromVersion: number,
  options: RotationOptions = {},
): Promise<RotationResult> {
  const batchSize = options.batchSize ?? 100;
  let cursor = options.cursor;
  let migrated = 0;

  for (;;) {
    const batch = await store.fetchBatch(fromVersion, cursor, batchSize);
    if (batch.length === 0) {
      return { migrated, cursor, done: true };
    }

    for (const record of batch) {
      const next = reencrypt(record.ciphertext, keyRing);
      if (next !== record.ciphertext) {
        await store.update(record.id, next);
        migrated += 1;
      }
    }

    cursor = batch[batch.length - 1].id;
    if (options.onProgress) {
      await options.onProgress(cursor, migrated);
    }

    if (batch.length < batchSize) {
      return { migrated, cursor, done: true };
    }
  }
}
