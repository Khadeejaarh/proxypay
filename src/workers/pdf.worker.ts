import { Worker, Job, Queue } from 'bullmq';
import PDFDocument from 'pdfkit';
import { PassThrough } from 'stream';
import { createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import { redisConnection } from '../config/redis';
import { logger } from '../utils/logger';
import { getReceiptData, getStatementData } from '../services/report.service';

// Bound CPU/memory: cap rows rendered per document and limit worker concurrency.
const MAX_RECEIPT_ROWS = 500;
const MAX_STATEMENT_ROWS = 5000;
const PDF_WORKER_CONCURRENCY = 2;

export const pdfQueue = new Queue('pdf-generation', {
  connection: redisConnection,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: 100,
    removeOnFail: 500,
  },
});

type PdfJobData = {
  type: 'receipt' | 'statement';
  id: string;
  outputPath: string;
};

function capRows<T>(rows: T[], max: number): T[] {
  if (rows.length > max) {
    logger.warn(`PDF row cap applied: ${rows.length} > ${max}`);
    return rows.slice(0, max);
  }
  return rows;
}

async function renderReceipt(doc: PDFKit.PDFDocument, id: string): Promise<void> {
  const receipt = await getReceiptData(id);
  const rows = capRows(receipt.items ?? [], MAX_RECEIPT_ROWS);

  doc.fontSize(18).text('Receipt', { align: 'center' });
  doc.moveDown();
  doc.fontSize(10).text(`Receipt ID: ${receipt.id}`);
  doc.text(`Date: ${receipt.date}`);
  doc.moveDown();

  for (const row of rows) {
    doc.text(`${row.description}  ${row.amount}`);
  }

  doc.moveDown();
  doc.text(`Total: ${receipt.total}`);
}

async function renderStatement(doc: PDFKit.PDFDocument, id: string): Promise<void> {
  const statement = await getStatementData(id);
  const rows = capRows(statement.transactions ?? [], MAX_STATEMENT_ROWS);

  doc.fontSize(18).text('Statement', { align: 'center' });
  doc.moveDown();
  doc.fontSize(10).text(`Account: ${statement.accountId}`);
  doc.text(`Period: ${statement.period}`);
  doc.moveDown();

  for (const row of rows) {
    doc.text(`${row.date}  ${row.description}  ${row.amount}`);
  }

  doc.moveDown();
  doc.text(`Closing Balance: ${statement.closingBalance}`);
}

async function processPdfJob(job: Job<PdfJobData>): Promise<void> {
  const { type, id, outputPath } = job.data;

  // Stream the document to disk instead of buffering the whole PDF in memory.
  const doc = new PDFDocument({ autoFirstPage: true });
  const sink = createWriteStream(outputPath);

  const renderPromise = (async () => {
    if (type === 'receipt') {
      await renderReceipt(doc, id);
    } else {
      await renderStatement(doc, id);
    }
    doc.end();
  })();

  await Promise.all([
    pipeline(doc as unknown as PassThrough, sink),
    renderPromise,
  ]);

  logger.info(`PDF generated: ${type} ${id} -> ${outputPath}`);
}

export const pdfWorker = new Worker<PdfJobData>('pdf-generation', processPdfJob, {
  connection: redisConnection,
  concurrency: PDF_WORKER_CONCURRENCY,
});

pdfWorker.on('failed', (job, err) => {
  logger.error(`PDF job ${job?.id} failed: ${err.message}`);
});

pdfWorker.on('error', (err) => {
  logger.error(`PDF worker error: ${err.message}`);
});
