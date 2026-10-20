import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'crypto';

export interface EncryptedValue {
  /** Ciphertext payload (base64). */
  ciphertext: string;
  /** Initialization vector (base64). */
  iv: string;
  /** Authentication tag (base64) for GCM. */
  authTag: string;
  /** Key version used to produce this ciphertext. */
  keyVersion: number;
}

export interface KeyMaterial {
  version: number;
  key: Buffer;
}

/**
 * Resolves key material for a given version. Implementations may wrap a KMS
 * or a local keyring. Must return the key for the requested version or throw.
 */
export type KeyResolver = (version: number) => Promise<KeyMaterial> | KeyMaterial;

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

export class KeyRotationService {
  constructor(
    private readonly resolveKey: KeyResolver,
    private readonly currentVersion: number,
  ) {}

  /** Encrypt a plaintext value using the current key version. */
  async encrypt(plaintext: string): Promise<EncryptedValue> {
    const { version, key } = await this.resolveKey(this.currentVersion);
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    return {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
      keyVersion: version,
    };
  }

  /**
   * Decrypt a value using the key version recorded on the record. This keeps
   * reads working during mixed-key rollout and rollback.
   */
  async decrypt(value: EncryptedValue): Promise<string> {
    const { key } = await this.resolveKey(value.keyVersion);
    const decipher = createDecipheriv(
      ALGORITHM,
      key,
      Buffer.from(value.iv, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(value.authTag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(value.ciphertext, 'base64')),
      decipher.final(),
    ]);
    return plaintext.toString('utf8');
  }

  /** True when the value is already encrypted with the current key version. */
  isCurrent(value: EncryptedValue): boolean {
    return value.keyVersion === this.currentVersion;
  }

  /**
   * Re-encrypt a single value to the current key version, verifying the
   * round-trip before returning. Returns the original value unchanged when it
   * is already current.
   */
  async reencrypt(value: EncryptedValue): Promise<EncryptedValue> {
    if (this.isCurrent(value)) {
      return value;
    }
    const plaintext = await this.decrypt(value);
    const rotated = await this.encrypt(plaintext);
    await this.verify(plaintext, rotated);
    return rotated;
  }

  /** Verify that a re-encrypted value decrypts back to the expected plaintext. */
  async verify(expected: string, value: EncryptedValue): Promise<void> {
    const actual = await this.decrypt(value);
    const a = Buffer.from(actual, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new Error(
        `Key rotation verification failed for key version ${value.keyVersion}`,
      );
    }
  }
}

export interface RotationRecord {
  id: string;
  value: EncryptedValue;
}

export interface RotationStore {
  /** Fetch a page of records still on an older key version, ordered by id. */
  fetchBatch(
    afterId: string | null,
    limit: number,
  ): Promise<RotationRecord[]>;
  /** Persist a re-encrypted value. Must be idempotent per record id. */
  save(id: string, value: EncryptedValue): Promise<void>;
  /** Persist a resumable cursor so an interrupted run can continue. */
  saveCursor(cursor: string | null): Promise<void>;
  /** Load the last persisted cursor, if any. */
  loadCursor(): Promise<string | null>;
}

export interface RotationResult {
  scanned: number;
  rotated: number;
  skipped: number;
  cursor: string | null;
  completed: boolean;
}

/**
 * Resumable batch re-encryption. Processes records in id-ordered pages,
 * verifying each re-encrypted value before committing it, and persists a
 * cursor so an interrupted run resumes where it left off.
 */
export class KeyRotationRunner {
  constructor(
    private readonly service: KeyRotationService,
    private readonly store: RotationStore,
    private readonly batchSize = 100,
  ) {}

  async run(): Promise<RotationResult> {
    let cursor = await this.store.loadCursor();
    let scanned = 0;
    let rotated = 0;
    let skipped = 0;

    for (;;) {
      const batch = await this.store.fetchBatch(cursor, this.batchSize);
      if (batch.length === 0) {
        await this.store.saveCursor(null);
        return { scanned, rotated, skipped, cursor: null, completed: true };
      }

      for (const record of batch) {
        scanned += 1;
        if (this.service.isCurrent(record.value)) {
          skipped += 1;
        } else {
          const next = await this.service.reencrypt(record.value);
          await this.store.save(record.id, next);
          rotated += 1;
        }
        cursor = record.id;
        await this.store.saveCursor(cursor);
      }

      if (batch.length < this.batchSize) {
        await this.store.saveCursor(null);
        return { scanned, rotated, skipped, cursor: null, completed: true };
      }
    }
  }
}
