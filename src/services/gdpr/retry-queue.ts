/**
 * Retry queue for GDPR archive operations that could not be durably
 * persisted (e.g. S3 upload failed and the archive only exists in memory).
 *
 * Records are persisted so a failed archive can be retried later instead of
 * being reported as successfully archived.
 */

export type ArchiveRetryStatus = "pending" | "failed";

export interface ArchiveRetryRecord {
  /** Stable identifier for the archive request. */
  id: string;
  /** Subject the archive belongs to. */
  subjectId: string;
  /** What kind of GDPR operation produced the archive. */
  operation: "export" | "purge";
  /** Current retry state; never "archived" until durably stored. */
  status: ArchiveRetryStatus;
  /** Number of attempts made so far. */
  attempts: number;
  /** Last error message, if any. */
  lastError?: string;
  /** ISO timestamp of when the record was created. */
  createdAt: string;
  /** ISO timestamp of the most recent attempt. */
  updatedAt: string;
}

export interface ArchiveRetryStore {
  save(record: ArchiveRetryRecord): Promise<void>;
  get(id: string): Promise<ArchiveRetryRecord | undefined>;
  list(): Promise<ArchiveRetryRecord[]>;
  remove(id: string): Promise<void>;
}

/**
 * In-memory fallback store. This is only used to persist retry records; it is
 * never treated as a durable archive location.
 */
export class InMemoryArchiveRetryStore implements ArchiveRetryStore {
  private readonly records = new Map<string, ArchiveRetryRecord>();

  async save(record: ArchiveRetryRecord): Promise<void> {
    this.records.set(record.id, { ...record });
  }

  async get(id: string): Promise<ArchiveRetryRecord | undefined> {
    const record = this.records.get(id);
    return record ? { ...record } : undefined;
  }

  async list(): Promise<ArchiveRetryRecord[]> {
    return Array.from(this.records.values(), (record) => ({ ...record }));
  }

  async remove(id: string): Promise<void> {
    this.records.delete(id);
  }
}

export interface EnqueueArchiveRetryInput {
  id: string;
  subjectId: string;
  operation: ArchiveRetryRecord["operation"];
  status?: ArchiveRetryStatus;
  error?: unknown;
}

function errorMessage(error: unknown): string | undefined {
  if (error === undefined || error === null) {
    return undefined;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

/**
 * Persist a retry record for an archive that could not be durably stored.
 * Returns the stored record so callers can surface an explicit failed/pending
 * state instead of reporting a false success.
 */
export async function enqueueArchiveRetry(
  store: ArchiveRetryStore,
  input: EnqueueArchiveRetryInput,
): Promise<ArchiveRetryRecord> {
  const now = new Date().toISOString();
  const existing = await store.get(input.id);

  const record: ArchiveRetryRecord = {
    id: input.id,
    subjectId: input.subjectId,
    operation: input.operation,
    status: input.status ?? "failed",
    attempts: (existing?.attempts ?? 0) + 1,
    lastError: errorMessage(input.error) ?? existing?.lastError,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };

  await store.save(record);
  return record;
}

/**
 * Whether a durable archive exists for the given retry record. A record that
 * is still pending or failed means no durable archive is available.
 */
export function hasDurableArchive(
  record: ArchiveRetryRecord | undefined,
): boolean {
  return record === undefined;
}

/**
 * Guard used before destructive purge. When policy requires a durable archive
 * and none exists, the purge must be blocked.
 */
export function assertDurableArchiveForPurge(
  record: ArchiveRetryRecord | undefined,
  requireDurableArchive: boolean,
): void {
  if (requireDurableArchive && !hasDurableArchive(record)) {
    throw new Error(
      `Cannot purge subject ${record?.subjectId ?? "unknown"}: no durable GDPR archive exists (status: ${record?.status ?? "missing"})`,
    );
  }
}
