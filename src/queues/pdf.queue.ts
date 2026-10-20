import { Queue, Worker, Job, QueueEvents } from 'bullmq';
import { Redis } from 'ioredis';
import PDFDocument from 'pdfkit';
import { PassThrough } from 'stream';

// Bounded limits to keep CPU/memory predictable under load.
export const PDF_MAX_ROWS = 5000;
export const PDF_WORKER_CONCURRENCY = 2;
export const PDF_MAX_ATTEMPTS = 3;

export interface PdfJobData {
  type: 'receipt' | 'statement';
  accountId: string;
  rows: Array<Record<string, unknown>>;
  meta?: Record<string, unknown>;
}

const connection = new Redis(process.env.REDIS_URL as string, {
  maxRetriesPerRequest: null,
});

export const pdfQueue = new Queue<PdfJobData>('pdf', {
  connection,
  defaultJobOptions: {
    attempts: PDF_MAX_ATTEMPTS,
    backoff: { type: 'exponential', delay: 1000 },
    removeOnComplete: 100,
    removeOnFail: 500,
  },
});

export const pdfQueueEvents = new QueueEvents('pdf', { connection });

/**
 * Cap the number of rows rendered so a single document cannot exhaust
 * CPU/memory. Returns the bounded slice plus whether truncation occurred.
 */
export function capRows<T>(rows: T[], max = PDF_MAX_ROWS): { rows: T[]; truncated: boolean } {
  if (rows.length <= max) {
    return { rows, truncated: false };
  }
  return { rows: rows.slice(0, max), truncated: true };
}

/**
 * Render a PDF as a stream instead of buffering the whole document in memory.
 * Callers can pipe the returned stream directly to a response or storage sink.
 */
export function renderPdfStream(data: PdfJobData): PassThrough {
  const { rows, truncated } = capRows(data.rows);
  const doc = new PDFDocument({ autoFirstPage: true });
  const out = new PassThrough();
  doc.pipe(out);

  doc.fontSize(16).text(data.type === 'receipt' ? 'Receipt' : 'Statement');
  doc.moveDown();
  doc.fontSize(10).text(`Account: ${data.accountId}`);
  if (truncated) {
    doc.moveDown();
    doc.text(`Note: output truncated to ${PDF_MAX_ROWS} rows.`);
  }
  doc.moveDown();

  for (const row of rows) {
    doc.text(JSON.stringify(row));
  }

  doc.end();
  return out;
}

/**
 * Bounded worker: concurrency is capped so heavy rendering cannot saturate
 * the process. Rendering is streamed and rows are capped per document.
 */
export const pdfWorker = new Worker<PdfJobData>(
  'pdf',
  async (job: Job<PdfJobData>) => {
    const stream = renderPdfStream(job.data);
    // Drain the stream to completion; a real sink (storage/response) can be
    // piped here. We avoid accumulating the full buffer in memory.
    await new Promise<void>((resolve, reject) => {
      stream.on('data', () => undefined);
      stream.on('end', () => resolve());
      stream.on('error', reject);
    });
    return { ok: true, rows: capRows(job.data.rows).rows.length };
  },
  {
    connection,
    concurrency: PDF_WORKER_CONCURRENCY,
  },
);
