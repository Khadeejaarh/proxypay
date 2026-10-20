import { Queue, Worker, Job, JobsOptions } from 'bullmq';
import IORedis from 'ioredis';
import { sendInvoiceEmail } from '../services/email';
import { Invoice, InvoiceStatus } from '../models/invoice';

const QUEUE_NAME = 'invoice-delivery';

const RESENDABLE_STATUSES: InvoiceStatus[] = [
  InvoiceStatus.SENT,
  InvoiceStatus.OVERDUE,
  InvoiceStatus.PAID,
];

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

let connection: IORedis | null = null;
let queue: Queue<InvoiceDeliveryJobData> | null = null;
let worker: Worker<InvoiceDeliveryJobData> | null = null;

export interface InvoiceDeliveryJobData {
  invoiceId: string;
  recipient: string;
  requestedBy?: string;
}

function getConnection(): IORedis {
  if (!connection) {
    connection = new IORedis(process.env.REDIS_URL || 'redis://127.0.0.1:6379', {
      maxRetriesPerRequest: null,
    });
  }
  return connection;
}

export function getInvoiceDeliveryQueue(): Queue<InvoiceDeliveryJobData> {
  if (!queue) {
    queue = new Queue<InvoiceDeliveryJobData>(QUEUE_NAME, {
      connection: getConnection(),
    });
  }
  return queue;
}

/**
 * Validate that an invoice can be resent and that it has a usable recipient.
 * Throws a descriptive error when validation fails.
 */
export function validateResendable(invoice: Invoice | null | undefined): string {
  if (!invoice) {
    throw new Error('Invoice not found');
  }
  if (!RESENDABLE_STATUSES.includes(invoice.status)) {
    throw new Error(`Invoice in status "${invoice.status}" cannot be resent`);
  }
  const recipient = (invoice.customerEmail || '').trim();
  if (!recipient || !EMAIL_REGEX.test(recipient)) {
    throw new Error('Invoice has no valid recipient email');
  }
  return recipient;
}

/**
 * Enqueue an idempotent invoice delivery job. The jobId is derived from the
 * invoice id and a caller-supplied idempotency key so duplicate requests do not
 * enqueue duplicate deliveries.
 */
export async function enqueueInvoiceDelivery(
  invoice: Invoice,
  idempotencyKey: string,
  requestedBy?: string,
): Promise<Job<InvoiceDeliveryJobData>> {
  const recipient = validateResendable(invoice);
  const jobId = `invoice-delivery:${invoice.id}:${idempotencyKey}`;
  const opts: JobsOptions = {
    jobId,
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: 1000,
    removeOnFail: 5000,
  };
  return getInvoiceDeliveryQueue().add(
    'deliver',
    { invoiceId: invoice.id, recipient, requestedBy },
    opts,
  );
}

/**
 * Process a delivery job: send the email, then update invoice status only after
 * the provider accepts the message. On final failure the invoice is marked as
 * failed so the state reflects reality.
 */
async function processDelivery(job: Job<InvoiceDeliveryJobData>): Promise<void> {
  const { invoiceId, recipient } = job.data;
  const invoice = await Invoice.findById(invoiceId);
  if (!invoice) {
    throw new Error(`Invoice ${invoiceId} no longer exists`);
  }

  // Re-validate at processing time in case state changed since enqueue.
  validateResendable(invoice);

  const result = await sendInvoiceEmail({
    to: recipient,
    invoice,
  });

  if (!result || !result.accepted) {
    throw new Error('Email provider did not accept the message');
  }

  invoice.status = InvoiceStatus.SENT;
  invoice.lastSentAt = new Date();
  await invoice.save();
}

export function startInvoiceDeliveryWorker(): Worker<InvoiceDeliveryJobData> {
  if (!worker) {
    worker = new Worker<InvoiceDeliveryJobData>(
      QUEUE_NAME,
      async (job) => {
        try {
          await processDelivery(job);
        } catch (err) {
          const attempts = job.opts.attempts ?? 1;
          const isFinalAttempt = job.attemptsMade + 1 >= attempts;
          if (isFinalAttempt) {
            const invoice = await Invoice.findById(job.data.invoiceId);
            if (invoice) {
              invoice.status = InvoiceStatus.FAILED;
              invoice.lastDeliveryError = (err as Error).message;
              await invoice.save();
            }
          }
          throw err;
        }
      },
      { connection: getConnection() },
    );
  }
  return worker;
}
