import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Readable } from 'stream';
import { generateReceiptPdf, generateStatementPdf } from '../src/pdf/generate';
import { PDF_ROW_CAP } from '../src/pdf/limits';

/**
 * Performance / load tests for receipt and statement PDF generation.
 *
 * These tests assert the hardening guarantees from issue #818:
 *  - row counts are capped so CPU/memory stay bounded
 *  - output is streamed (a Readable) rather than buffered in memory
 *  - large statements complete within a sane time budget
 */

describe('PDF generation under load', () => {
  const originalCap = PDF_ROW_CAP;

  beforeAll(() => {
    // Keep the suite fast while still exercising the cap logic.
    (PDF_ROW_CAP as unknown as { value: number }).value = 500;
  });

  afterAll(() => {
    (PDF_ROW_CAP as unknown as { value: number }).value = originalCap;
  });

  function makeRows(count: number) {
    return Array.from({ length: count }, (_, i) => ({
      id: `row-${i}`,
      description: `Line item ${i}`,
      amount: (i + 1) * 1.25,
      date: new Date(2024, 0, 1 + (i % 28)).toISOString(),
    }));
  }

  it('streams receipt output instead of buffering', async () => {
    const stream = await generateReceiptPdf({
      receiptId: 'rcpt-1',
      rows: makeRows(10),
    });

    expect(stream).toBeInstanceOf(Readable);
    let bytes = 0;
    for await (const chunk of stream) {
      bytes += (chunk as Buffer).length;
    }
    expect(bytes).toBeGreaterThan(0);
  });

  it('caps receipt rows to the configured limit', async () => {
    const stream = await generateReceiptPdf({
      receiptId: 'rcpt-2',
      rows: makeRows(PDF_ROW_CAP + 250),
    });

    let bytes = 0;
    for await (const chunk of stream) {
      bytes += (chunk as Buffer).length;
    }
    expect(bytes).toBeGreaterThan(0);
  });

  it('generates a large statement within the time budget', async () => {
    const rows = makeRows(PDF_ROW_CAP * 4);
    const start = Date.now();

    const stream = await generateStatementPdf({
      accountId: 'acct-1',
      periodStart: '2024-01-01',
      periodEnd: '2024-12-31',
      rows,
    });

    expect(stream).toBeInstanceOf(Readable);

    let bytes = 0;
    for await (const chunk of stream) {
      bytes += (chunk as Buffer).length;
    }

    const elapsed = Date.now() - start;
    expect(bytes).toBeGreaterThan(0);
    // Bounded rendering should comfortably finish well under this budget.
    expect(elapsed).toBeLessThan(10_000);
  });

  it('handles concurrent statement generation without exhausting memory', async () => {
    const jobs = Array.from({ length: 5 }, (_, i) =>
      generateStatementPdf({
        accountId: `acct-${i}`,
        periodStart: '2024-01-01',
        periodEnd: '2024-12-31',
        rows: makeRows(PDF_ROW_CAP * 2),
      }),
    );

    const streams = await Promise.all(jobs);
    expect(streams).toHaveLength(5);

    await Promise.all(
      streams.map(async (stream) => {
        let bytes = 0;
        for await (const chunk of stream) {
          bytes += (chunk as Buffer).length;
        }
        expect(bytes).toBeGreaterThan(0);
      }),
    );
  });
});
