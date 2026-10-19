/**
 * PII record model with key-version metadata so ciphertext versions are
 * identifiable at read time and can be migrated across key rotations.
 */

export interface PiiRecord {
  id: string;
  /** Logical field/column the ciphertext belongs to (e.g. "email"). */
  field: string;
  /** Encrypted value (ciphertext, base64/opaque). */
  ciphertext: string;
  /** Key version used to produce `ciphertext`. */
  keyVersion: number;
  /** Optional nonce/IV for AEAD schemes. */
  nonce?: string;
  /** Optional auth tag for AEAD schemes. */
  authTag?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * Cursor for resumable re-encryption batches. Persist this so a migration can
 * resume after interruption without re-processing or skipping records.
 */
export interface ReencryptionCursor {
  /** Key version being migrated away from. */
  fromVersion: number;
  /** Key version being migrated to. */
  toVersion: number;
  /** Last successfully migrated record id (exclusive resume point). */
  lastId: string | null;
  /** Number of records migrated so far. */
  migrated: number;
  /** Whether the migration has completed. */
  completed: boolean;
  updatedAt: string;
}

/**
 * Result of verifying a re-encrypted value before committing the migration.
 */
export interface ReencryptionVerification {
  recordId: string;
  ok: boolean;
  /** Reason verification failed, when `ok` is false. */
  reason?: string;
}

/**
 * Decrypts a ciphertext using the key version recorded on the record, so reads
 * keep working during mixed-key rollout and rollback.
 */
export type DecryptWithVersion = (
  ciphertext: string,
  keyVersion: number,
  nonce?: string,
  authTag?: string,
) => string;

/**
 * Encrypts a plaintext value with the target key version.
 */
export type EncryptWithVersion = (
  plaintext: string,
  keyVersion: number,
) => { ciphertext: string; nonce?: string; authTag?: string };

/**
 * Reads a PII record by decrypting with the version stored on the record.
 * This is the mixed-key-safe read path: it never assumes the current key.
 */
export function readPiiRecord(
  record: PiiRecord,
  decrypt: DecryptWithVersion,
): string {
  return decrypt(record.ciphertext, record.keyVersion, record.nonce, record.authTag);
}

/**
 * Re-encrypts a single record to `toVersion` and verifies the result by
 * decrypting the new ciphertext and comparing it to the original plaintext.
 * Returns the updated record only when verification succeeds.
 */
export function reencryptPiiRecord(
  record: PiiRecord,
  toVersion: number,
  decrypt: DecryptWithVersion,
  encrypt: EncryptWithVersion,
  now: string = new Date().toISOString(),
): { record: PiiRecord; verification: ReencryptionVerification } {
  if (record.keyVersion === toVersion) {
    return {
      record,
      verification: { recordId: record.id, ok: true },
    };
  }

  let plaintext: string;
  try {
    plaintext = decrypt(record.ciphertext, record.keyVersion, record.nonce, record.authTag);
  } catch (err) {
    return {
      record,
      verification: {
        recordId: record.id,
        ok: false,
        reason: `decrypt failed: ${(err as Error).message}`,
      },
    };
  }

  const encrypted = encrypt(plaintext, toVersion);
  const candidate: PiiRecord = {
    ...record,
    ciphertext: encrypted.ciphertext,
    keyVersion: toVersion,
    nonce: encrypted.nonce,
    authTag: encrypted.authTag,
    updatedAt: now,
  };

  let roundTrip: string;
  try {
    roundTrip = decrypt(candidate.ciphertext, candidate.keyVersion, candidate.nonce, candidate.authTag);
  } catch (err) {
    return {
      record,
      verification: {
        recordId: record.id,
        ok: false,
        reason: `verify decrypt failed: ${(err as Error).message}`,
      },
    };
  }

  if (roundTrip !== plaintext) {
    return {
      record,
      verification: {
        recordId: record.id,
        ok: false,
        reason: "verify mismatch: decrypted value differs from original",
      },
    };
  }

  return {
    record: candidate,
    verification: { recordId: record.id, ok: true },
  };
}
