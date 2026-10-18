/**
 * Runtime query-validation schema shared by the transactions list middleware
 * and the OpenAPI generator (issue #812).
 *
 * `validateTransactionFilters` (src/utils/transactionFilters.ts) parses the
 * list-query parameters through this schema, and `src/openapi/paths/
 * transactions.ts` registers the same object — the documented constraints
 * always match what the endpoint accepts.
 */

import { z } from "zod";

export const listTransactionsQuerySchema = z.object({
  status: z
    .string()
    .optional()
    .describe(
      "Comma-separated transaction statuses and/or named ranges (terminal, active, success, failure)",
    ),
  limit: z.coerce.number().int().min(1).max(1000).default(50),
  offset: z.coerce.number().int().min(0).default(0),
  reference: z.string().optional(),
});

export type ListTransactionsQuery = z.infer<typeof listTransactionsQuerySchema>;
