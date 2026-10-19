import axios, { AxiosError } from "axios";
import { config } from "../config/env";
import logger from "../logger";

interface CreatePaymentPayload {
  amount: number;
  currency: string;
}

interface CreatePaymentResponse {
  id: string;
  status: string;
}

interface PaymentStatusResponse {
  id: string;
  status: string;
}

/**
 * Persisted SEP-31 transaction reference. The `reference` is unique per
 * payout attempt and is written before any external call so retries can
 * reconcile against provider state instead of submitting a second payout.
 */
export interface Sep31TransactionRecord {
  reference: string;
  status: "pending" | "submitted" | "completed" | "failed";
  providerPaymentId?: string;
}

/**
 * Minimal persistence contract. Implementations MUST enforce a uniqueness
 * constraint on `reference` (e.g. a unique index) so concurrent retries
 * cannot create duplicate payout records.
 */
export interface Sep31TransactionStore {
  /** Inserts a new record; must throw on duplicate `reference`. */
  create(record: Sep31TransactionRecord): Promise<void>;
  findByReference(reference: string): Promise<Sep31TransactionRecord | null>;
  update(record: Sep31TransactionRecord): Promise<void>;
}

const client = axios.create({
  baseURL: config.bridgeApiUrl,
  headers: {
    // Authorization header is redacted by the pino logger — never logged.
    Authorization: `Bearer ${config.bridgeApiKey}`,
    "Content-Type": "application/json",
  },
});

/**
 * Creates a payment via the Bridge API.
 * Logs the outbound request and any error response as structured JSON.
 * The Authorization header is automatically redacted by the logger.
 */
export const createPayment = async (
  payload: CreatePaymentPayload,
): Promise<CreatePaymentResponse> => {
  logger.debug(
    { amount: payload.amount, currency: payload.currency },
    "Sending payment request to Bridge API",
  );

  try {
    const response = await client.post<CreatePaymentResponse>(
      "/payments",
      payload,
    );

    logger.info(
      {
        paymentId: response.data.id,
        status: response.data.status,
        amount: payload.amount,
        currency: payload.currency,
      },
      "Bridge API payment created",
    );

    return response.data;
  } catch (err) {
    const axiosErr = err as AxiosError<{ message?: string }>;

    logger.error(
      {
        err: {
          message: axiosErr.message,
          status: axiosErr.response?.status,
          // Response body may contain useful error details but never secrets.
          responseData: axiosErr.response?.data,
        },
        amount: payload.amount,
        currency: payload.currency,
      },
      "Bridge API request failed",
    );

    throw err;
  }
};

/**
 * Queries the provider status API for an existing payout by reference.
 * Returns null when the provider has no record of the payout.
 */
export const getPaymentByReference = async (
  reference: string,
): Promise<PaymentStatusResponse | null> => {
  try {
    const response = await client.get<PaymentStatusResponse>(
      `/payments/by-reference/${encodeURIComponent(reference)}`,
    );
    return response.data;
  } catch (err) {
    const axiosErr = err as AxiosError;
    if (axiosErr.response?.status === 404) {
      return null;
    }
    throw err;
  }
};

/**
 * Idempotent SEP-31 payout submission.
 *
 * 1. Persists a unique transaction reference before any external call.
 * 2. On ambiguous failures (timeouts / unknown responses), queries the
 *    provider status API to determine whether the payout already exists
 *    before retrying.
 * 3. Reconciles the persisted reference with the provider payment id so
 *    duplicate/out-of-order completion callbacks cannot create a second
 *    payout.
 */
export const submitSep31Payout = async (
  store: Sep31TransactionStore,
  reference: string,
  payload: CreatePaymentPayload,
): Promise<Sep31TransactionRecord> => {
  // Persist the reference first. A duplicate reference means another attempt
  // already owns this payout — reconcile against it instead of resubmitting.
  let record = await store.findByReference(reference);
  if (!record) {
    try {
      await store.create({ reference, status: "pending" });
      record = { reference, status: "pending" };
    } catch (err) {
      // Uniqueness constraint hit: another attempt persisted it concurrently.
      record = await store.findByReference(reference);
      if (!record) {
        throw err;
      }
    }
  }

  // Already submitted or completed — never submit a second payout.
  if (record.status === "submitted" || record.status === "completed") {
    return record;
  }

  try {
    const payment = await createPayment(payload);
    record = {
      reference,
      status: "submitted",
      providerPaymentId: payment.id,
    };
    await store.update(record);
    return record;
  } catch (err) {
    const axiosErr = err as AxiosError;
    const status = axiosErr.response?.status;
    const ambiguous = !status || status >= 500 || axiosErr.code === "ECONNABORTED";

    if (!ambiguous) {
      // Definite rejection — safe to mark failed.
      record = { ...record, status: "failed" };
      await store.update(record);
      throw err;
    }

    // Ambiguous failure: query provider state before deciding to retry.
    logger.warn(
      { reference, status, code: axiosErr.code },
      "Ambiguous payout failure; reconciling with provider status",
    );

    const existing = await getPaymentByReference(reference);
    if (existing) {
      record = {
        reference,
        status: "submitted",
        providerPaymentId: existing.id,
      };
      await store.update(record);
      return record;
    }

    // Provider has no record — safe to retry once.
    const payment = await createPayment(payload);
    record = {
      reference,
      status: "submitted",
      providerPaymentId: payment.id,
    };
    await store.update(record);
    return record;
  }
};

/**
 * Reconciles a completion callback against the persisted reference.
 * Duplicate or out-of-order callbacks are ignored once the payout is
 * already completed, preventing a second payout from being created.
 */
export const reconcileSep31Callback = async (
  store: Sep31TransactionStore,
  reference: string,
  providerPaymentId: string,
): Promise<Sep31TransactionRecord> => {
  const record = await store.findByReference(reference);
  if (!record) {
    throw new Error(`Unknown SEP-31 reference: ${reference}`);
  }

  if (record.status === "completed") {
    return record;
  }

  if (record.providerPaymentId && record.providerPaymentId !== providerPaymentId) {
    logger.warn(
      { reference, expected: record.providerPaymentId, received: providerPaymentId },
      "Ignoring callback with mismatched provider payment id",
    );
    return record;
  }

  const updated: Sep31TransactionRecord = {
    ...record,
    status: "completed",
    providerPaymentId: record.providerPaymentId ?? providerPaymentId,
  };
  await store.update(updated);
  return updated;
};
