import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { randomUUID } from 'crypto';
import { logger } from '../../utils/logger';
import { retryQueue } from '../../utils/retryQueue';

export type ArchiveState = 'archived' | 'pending' | 'failed';

export interface ArchiveResult {
  archived: boolean;
  state: ArchiveState;
  key: string | null;
  retryId?: string;
  error?: string;
}

export interface ArchiveOptions {
  /** When true, callers must treat a non-durable archive as a hard failure. */
  requireDurable?: boolean;
}

const s3 = new S3Client({ region: process.env.AWS_REGION });
const BUCKET = process.env.GDPR_ARCHIVE_BUCKET;

export class GdprArchiveService {
  async archive(
    userId: string,
    payload: Buffer,
    options: ArchiveOptions = {},
  ): Promise<ArchiveResult> {
    const key = `gdpr/${userId}/${randomUUID()}.json`;

    if (!BUCKET) {
      return this.handleFailure(
        userId,
        key,
        payload,
        'GDPR_ARCHIVE_BUCKET is not configured',
        options,
      );
    }

    try {
      await s3.send(
        new PutObjectCommand({
          Bucket: BUCKET,
          Key: key,
          Body: payload,
          ContentType: 'application/json',
        }),
      );

      return { archived: true, state: 'archived', key };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('GDPR archive upload failed', { userId, key, error: message });
      return this.handleFailure(userId, key, payload, message, options);
    }
  }

  private async handleFailure(
    userId: string,
    key: string,
    payload: Buffer,
    error: string,
    options: ArchiveOptions,
  ): Promise<ArchiveResult> {
    // Persist a retry record so the archive can be retried later. The archive
    // is NOT durably retained, so we never report it as successfully archived.
    let retryId: string | undefined;
    try {
      retryId = await retryQueue.enqueue({
        type: 'gdpr-archive',
        userId,
        key,
        payload: payload.toString('base64'),
        error,
        createdAt: new Date().toISOString(),
      });
    } catch (queueErr) {
      logger.error('Failed to persist GDPR archive retry record', {
        userId,
        key,
        error: queueErr instanceof Error ? queueErr.message : String(queueErr),
      });
    }

    return {
      archived: false,
      state: options.requireDurable ? 'failed' : 'pending',
      key: null,
      retryId,
      error,
    };
  }

  /**
   * Guard destructive purge operations. When policy requires a durable archive,
   * purge must be blocked unless a durable archive actually exists.
   */
  assertPurgeAllowed(result: ArchiveResult, options: ArchiveOptions = {}): void {
    if (options.requireDurable && result.state !== 'archived') {
      throw new Error(
        `Refusing to purge: durable GDPR archive required but archive state is '${result.state}'`,
      );
    }
  }
}

export const gdprArchiveService = new GdprArchiveService();
