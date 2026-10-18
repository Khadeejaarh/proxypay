import { Request, Response, NextFunction } from "express";
import { listTransactionsQuerySchema } from "../validation/transactionQuerySchemas";

/**
 * Transaction Status Enum
 */
export enum TransactionStatus {
  Pending = "pending",
  Completed = "completed",
  Failed = "failed",
  Cancelled = "cancelled",
  Review = "review",
  Dispute = "dispute",
  Reversed = "reversed",
  ClawedBack = "clawed_back",
}

/**
 * Valid status values
 */
export const VALID_STATUSES = Object.values(TransactionStatus);

/**
 * Named status ranges. These can be used directly in the `status` query
 * parameter (Issue #633) to express compound/OR filters such as "every
 * terminal transaction" without enumerating each status by hand.
 *
 * Example: `?status=terminal`
 */
export const STATUS_RANGES: Record<string, TransactionStatus[]> = {
  /** Transactions that will not change state any further. */
  terminal: [
    TransactionStatus.Completed,
    TransactionStatus.Failed,
    TransactionStatus.Cancelled,
    TransactionStatus.Reversed,
    TransactionStatus.ClawedBack,
  ],
  /** Transactions still being processed. */
  active: [
    TransactionStatus.Pending,
    TransactionStatus.Review,
    TransactionStatus.Dispute,
  ],
  /** Successfully settled transactions. */
  success: [TransactionStatus.Completed],
  successful: [TransactionStatus.Completed],
  /** Transactions that ended unsuccessfully. */
  failure: [
    TransactionStatus.Failed,
    TransactionStatus.Cancelled,
    TransactionStatus.Reversed,
    TransactionStatus.ClawedBack,
  ],
};

/** Convenience aliases for the most common ranges. */
export const TERMINAL_STATUSES: TransactionStatus[] = STATUS_RANGES.terminal;
export const ACTIVE_STATUSES: TransactionStatus[] = STATUS_RANGES.active;

/** Reserved tokens that expand to a status range instead of a single status. */
export const STATUS_RANGE_NAMES = Object.keys(STATUS_RANGES);

/**
 * Query parameters interface
 */
export interface TransactionFilters {
  statuses: TransactionStatus[];
  limit: number;
  offset: number;
  sortBy?: string;
  sortOrder?: "ASC" | "DESC";
  reference?: string;
}

/** Remove duplicates while preserving the original order. */
const dedupeStatuses = (statuses: TransactionStatus[]): TransactionStatus[] =>
  Array.from(new Set(statuses));

/**
 * Expand status tokens, resolving named ranges (e.g. `terminal`) into their
 * concrete statuses. Throws if any token is neither a valid status nor a
 * known range name.
 */
export const expandStatusTokens = (tokens: string[]): TransactionStatus[] => {
  const invalid: string[] = [];
  const expanded: TransactionStatus[] = [];

  for (const token of tokens) {
    const range = STATUS_RANGES[token];
    if (range) {
      expanded.push(...range);
      continue;
    }

    if (VALID_STATUSES.includes(token as TransactionStatus)) {
      expanded.push(token as TransactionStatus);
      continue;
    }

    invalid.push(token);
  }

  if (invalid.length > 0) {
    throw new Error(
      `Invalid status values: ${invalid.join(", ")}. Valid values are: ${VALID_STATUSES.join(
        ", ",
      )}. Valid ranges are: ${STATUS_RANGE_NAMES.join(", ")}`,
    );
  }

  return dedupeStatuses(expanded);
};

/**
 * Parse and validate status query parameter.
 *
 * Supports:
 *  - single status:      ?status=pending
 *  - compound (OR):      ?status=pending,completed,failed
 *  - named ranges:       ?status=terminal
 *  - ranges + statuses:  ?status=terminal,review
 *
 * An omitted/blank value means "no filter" and expands to every valid status
 * at query time (see `listTransactionsHandler`, which expands an empty filter
 * to the full status set).
 *
 * @param statusParam Status query parameter value
 * @returns Array of valid status values (empty when no filter was provided)
 * @throws Error if an invalid status or range is provided
 */
export const parseStatusFilter = (
  statusParam?: string,
): TransactionStatus[] => {
  if (!statusParam) {
    return [];
  }

  const tokens = String(statusParam)
    .trim()
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0 && !/^[-]+$/.test(s));

  if (tokens.length === 0) {
    return [];
  }

  return expandStatusTokens(tokens);
};

/**
 * Build WHERE clause for status filtering. Multiple statuses are combined with
 * OR logic via SQL `IN` (Issue #633).
 * @param statuses Array of statuses to filter by
 * @returns SQL WHERE clause fragment
 */
export const buildStatusWhereClause = (
  statuses: TransactionStatus[],
): string => {
  const unique = dedupeStatuses(statuses);
  if (unique.length === 0) return "";
  if (unique.length === VALID_STATUSES.length) return "";

  const values = unique.map((status) => `'${status}'`).join(", ");
  return `status IN (${values})`;
};

/** True when a status represents a terminal (no further state change) state. */
export const isTerminalStatus = (status: TransactionStatus): boolean =>
  TERMINAL_STATUSES.includes(status);

/**
 * Middleware: Validate and parse transaction filters
 */
export const validateTransactionFilters = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { status, limit, offset, reference } = req.query;

    // Parse the query through the shared Zod contract so runtime parsing and
    // the OpenAPI spec are always in sync (issue #812).
    const parsed = listTransactionsQuerySchema.safeParse({
      status,
      limit: limit ?? undefined,
      offset: offset ?? undefined,
      reference: reference ?? undefined,
    });

    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const field = issue?.path?.[0];
      if (field === "limit") {
        return res.status(400).json({
          error: "Invalid limit parameter",
          message: "limit must be a number between 1 and 1000",
        });
      }
      if (field === "offset") {
        return res.status(400).json({
          error: "Invalid offset parameter",
          message: "offset must be a non-negative number",
        });
      }
      return res.status(400).json({
        error: "Invalid query parameters",
        message: issue?.message ?? "Invalid query parameters",
      });
    }

    const { limit: cappedLimit, offset: offsetNum, reference: referenceValue } =
      parsed.data;

    // Parse and validate status
    let statuses: TransactionStatus[] = [];
    try {
      statuses = parseStatusFilter(
        typeof status === "string" ? status : undefined
      );
    } catch (error) {
      return res.status(400).json({
        error: "Invalid status parameter",
        message: (error as Error).message,
        validStatuses: VALID_STATUSES,
      });
    }

    // Attach filters to request
    (req as any).transactionFilters = {
      statuses,
      limit: cappedLimit,
      offset: offsetNum,
      reference: referenceValue,
    };

    next();
  } catch (error) {
    res.status(500).json({
      error: "Error validating filters",
      message: (error as Error).message,
    });
  }
};

/**
 * Helper: Build paginated query info
 */
export const getPaginationInfo = (
  total: number,
  limit: number,
  offset: number
) => {
  return {
    total,
    limit,
    offset,
    hasMore: offset + limit < total,
    totalPages: Math.ceil(total / limit),
    currentPage: Math.floor(offset / limit) + 1,
  };
};
