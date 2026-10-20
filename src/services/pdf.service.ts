import PDFDocument from 'pdfkit';
import { PassThrough, Readable } from 'stream';
import { Queue, Worker, Job } from 'bullmq';
import { redisConnection } from '../config/redis';
import { logger } from '../utils/logger';

/**
 * Hard caps to bound CPU/memory when rendering receipts and statements.
 * Rows beyond these limits are truncated so a single oversized report
 * cannot exhaust worker resources.
 */
export const MAX_RECEIPT_ROWS = 500;
export const MAX_STATEMENT_ROWS = 5000;

/** Bounded concurrency for the PDF rendering worker. */
export const PDF_WORKER_CONCURRENCY = 2;

export interface ReceiptRow {
  description: string;
  quantity: number;
  amount: number;
}

export interface StatementRow {
  date: string;
  description: string;
  amount: number;
  balance: number;
}

export interface ReceiptData {
  receiptNumber: string;
  customerName: string;
  rows: ReceiptRow[];
  total: number;
}

export interface StatementData {
  accountName: string;
  periodStart: string;
  periodEnd: string;
  rows: StatementRow[];
}

export type PdfJobType = 'receipt' | 'statement';

export interface PdfJobData {
  type: PdfJobType;
  payload: ReceiptData | StatementData;
}

function capRows<T>(rows: T[], max: number): T[] {
  if (rows.length <= max) {
    return rows;
  }
  logger.warn(`PDF row cap exceeded: truncating ${rows.length} rows to ${max}`);
  return rows.slice(0, max);
}

/**
 * Render a receipt into a streaming PDF document. The returned stream emits
 * chunks as they are produced so callers never buffer the whole document.
 */
export function streamReceipt(data: ReceiptData): Readable {
  const doc = new PDFDocument({ margin: 40 });
  const out = new PassThrough();
  doc.pipe(out);

  doc.fontSize(18).text('Receipt', { align: 'center' });
  doc.moveDown();
  doc.fontSize(10).text(`Receipt #: ${data.receiptNumber}`);
  doc.text(`Customer: ${data.customerName}`);
  doc.moveDown();

  const rows = capRows(data.rows, MAX_RECEIPT_ROWS);
  for (const row of rows) {
    doc.text(
      `${row.description}  x${row.quantity}  ${row.amount.toFixed(2)}`,
    );
  }

  doc.moveDown();
  doc.fontSize(12).text(`Total: ${data.total.toFixed(2)}`, { align: 'right' });
  doc.end();

  return out;
}

/**
 * Render a statement into a streaming PDF document, capping rows to bound
 * CPU/memory usage for large statements.
 */
export function streamStatement(data: StatementData): Readable {
  const doc = new PDFDocument({ margin: 40 });
  const out = new PassThrough();
  doc.pipe(out);

  doc.fontSize(18).text('Statement', { align: 'center' });
  doc.moveDown();
  doc.fontSize(10).text(`Account: ${data.accountName}`);
  doc.text(`Period: ${data.periodStart} - ${data.periodEnd}`);
  doc.moveDown();

  const rows = capRows(data.rows, MAX_STATEMENT_ROWS);
  for (const row of rows) {
    doc.text(
      `${row.date}  ${row.description}  ${row.amount.toFixed(2)}  ${row.balance.toFixed(2)}`,
    );
  }

  doc.end();

  return out;
}

/**
 * Render a PDF job payload to a stream. Used by the bounded worker so heavy
 * rendering never runs synchronously on the request path.
 */
export function renderPdfStream(job: PdfJobData): Readable {
  if (job.type === 'receipt') {
    return streamReceipt(job.payload as ReceiptData);
  }
  return streamStatement(job.payload as StatementData);
}

/**
 * Bounded BullMQ queue for PDF rendering. Concurrency is capped so a burst of
 * large reports cannot saturate CPU/memory.
 */
export const pdfQueue = new Queue<PdfJobData>('pdf-generation', {
  connection: redisConnection,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 2000 },
    removeOnComplete: 100,
    removeOnFail: 500,
  },
});

/**
 * Enqueue a PDF rendering job. Returns the job id so callers can poll status
 * instead of rendering synchronously.
 */
export async function enqueuePdfJob(job: PdfJobData): Promise<string | undefined> {
  const created = await pdfQueue.add('render', job);
  return created.id;
}

/**
 * Bounded worker that renders PDFs off the request path. Concurrency is
 * limited to keep CPU/memory usage predictable under load.
 */
export function createPdfWorker(
  onStream: (jobId: string, stream: Readable) => Promise<void>,
): Worker<PdfJobData> {
  return new Worker<PdfJobData>(
    'pdf-generation',
    async (job: Job<PdfJobData>) => {
      const stream = renderPdfStream(job.data);
      await onStream(job.id ?? '', stream);
    },
    {
      connection: redisConnection,
      concurrency: PDF_WORKER_CONCURRENCY,
    },
  );
}
