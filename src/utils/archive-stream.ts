import { PassThrough, Transform, TransformCallback } from 'stream';
import archiver from 'archiver';
import { Upload } from '@aws-sdk/lib-storage';
import type { Response } from 'express';

export interface ArchiveStreamLimits {
  /** Maximum total uncompressed bytes that may be added to the archive. */
  maxBytes?: number;
  /** Maximum wall-clock time (ms) the export may run before being aborted. */
  maxDurationMs?: number;
}

export interface ArchiveStreamOptions extends ArchiveStreamLimits {
  /** ZIP format passed through to archiver. */
  format?: 'zip' | 'tar';
  /** Compression level (0-9). */
  zlibLevel?: number;
}

export class ExportLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExportLimitError';
  }
}

const DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB
const DEFAULT_MAX_DURATION_MS = 15 * 60 * 1000; // 15 minutes

/**
 * A bounded, backpressure-aware archive stream.
 *
 * Bytes are produced by archiver and piped through a size/time guard before
 * reaching the consumer. Because the guard is a Transform in the pipeline,
 * Node's stream backpressure naturally pauses archiver when the consumer
 * (HTTP response or S3 upload) is slow, keeping memory bounded.
 */
export class ArchiveStream {
  readonly archive: archiver.Archiver;
  private readonly guard: Transform;
  private readonly output: PassThrough;
  private readonly maxBytes: number;
  private readonly maxDurationMs: number;
  private bytesWritten = 0;
  private timer?: NodeJS.Timeout;
  private aborted = false;

  constructor(options: ArchiveStreamOptions = {}) {
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.maxDurationMs = options.maxDurationMs ?? DEFAULT_MAX_DURATION_MS;

    this.archive = archiver(options.format ?? 'zip', {
      zlib: { level: options.zlibLevel ?? 6 },
    });

    this.guard = new Transform({
      transform: (chunk: Buffer, _enc, cb: TransformCallback) => {
        if (this.aborted) {
          cb(new ExportLimitError('Export aborted'));
          return;
        }
        this.bytesWritten += chunk.length;
        if (this.bytesWritten > this.maxBytes) {
          this.abort(new ExportLimitError(`Export exceeded size limit of ${this.maxBytes} bytes`));
          cb(new ExportLimitError('Export exceeded size limit'));
          return;
        }
        cb(null, chunk);
      },
    });

    this.output = new PassThrough();

    this.archive.on('error', (err) => this.output.destroy(err));
    this.guard.on('error', (err) => this.output.destroy(err));

    this.archive.pipe(this.guard).pipe(this.output);

    this.timer = setTimeout(() => {
      this.abort(new ExportLimitError(`Export exceeded time limit of ${this.maxDurationMs}ms`));
    }, this.maxDurationMs);
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  /** Add a file from a buffer or readable stream. */
  append(source: Buffer | NodeJS.ReadableStream, name: string): this {
    this.archive.append(source as any, { name });
    return this;
  }

  /** Add a directory of files. */
  directory(dirPath: string, destPath: string): this {
    this.archive.directory(dirPath, destPath);
    return this;
  }

  /** Finalize the archive; resolves when all bytes have been flushed. */
  async finalize(): Promise<void> {
    await this.archive.finalize();
    await new Promise<void>((resolve, reject) => {
      this.output.once('end', resolve);
      this.output.once('error', reject);
      this.output.resume();
    });
    this.cleanup();
  }

  /** Stream the archive directly to an HTTP response. */
  pipeToResponse(res: Response): void {
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="export.zip"');
    this.output.on('error', (err) => {
      if (!res.headersSent) {
        res.status(500).end();
      } else {
        res.destroy(err);
      }
    });
    this.output.pipe(res);
  }

  /**
   * Stream the archive to S3 via multipart upload.
   * lib-storage consumes the readable with backpressure, so memory stays bounded.
   */
  async pipeToS3(params: {
    bucket: string;
    key: string;
    client: any;
    partSize?: number;
    queueSize?: number;
  }): Promise<void> {
    const upload = new Upload({
      client: params.client,
      params: { Bucket: params.bucket, Key: params.key, Body: this.output },
      partSize: params.partSize ?? 8 * 1024 * 1024,
      queueSize: params.queueSize ?? 4,
    });
    await upload.done();
    this.cleanup();
  }

  /** Abort the export, destroying the pipeline with the given error. */
  abort(err: Error): void {
    if (this.aborted) return;
    this.aborted = true;
    this.archive.abort();
    this.guard.destroy(err);
    this.output.destroy(err);
    this.cleanup();
  }

  private cleanup(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }
}
