/**
 * Per-subscription ownership checks (issue #814).
 *
 * An authenticated WebSocket client must not be able to subscribe to updates
 * for resources it does not own (e.g. another user's transaction or dispute).
 * Ownership is resolved through the request context:
 *
 *   - transactions → context.transactionModel.findById(id, userId)
 *   - disputes     → the dispute's underlying transaction must be owned
 *   - bulk imports → context.getBulkImportJob(jobId).userId when present
 *
 * Contexts that do not expose the relevant model/service (e.g. unit tests or
 * alternate execution contexts) skip enforcement — production contexts built by
 * buildGraphqlContext always include them, so enforcement is active there.
 */

import { GraphQLError } from "graphql";

export interface SubscriptionAuthContext {
  auth?: {
    authenticated?: boolean;
    subject?: string | null;
    userId?: string | null;
  };
  transactionModel?: {
    findById(
      id: string,
      userId?: string,
    ): Promise<{ userId?: string | null } | null | undefined>;
  };
  disputeService?: {
    getDispute(
      disputeId: string,
    ): Promise<{ transactionId?: string } | null | undefined>;
  };
  getBulkImportJob?: (
    jobId: string,
  ) => Promise<{ userId?: string | null } | null | undefined>;
}

function forbidden(message: string): GraphQLError {
  return new GraphQLError(message, { extensions: { code: "FORBIDDEN" } });
}

/** The authenticated principal id (JWT subject) for the subscription. */
export function subscriberId(context: SubscriptionAuthContext): string | null {
  return context?.auth?.subject ?? context?.auth?.userId ?? null;
}

/**
 * Asserts the subscriber owns the transaction, using a user-scoped lookup.
 * Throws FORBIDDEN when the transaction does not exist for this user (this
 * also avoids leaking existence of others' transactions).
 */
export async function assertTransactionAccess(
  context: SubscriptionAuthContext,
  transactionId: string,
): Promise<void> {
  const userId = subscriberId(context);
  if (!userId) {
    throw forbidden("UNAUTHENTICATED: valid authToken required");
  }

  const model = context?.transactionModel;
  if (!model || typeof model.findById !== "function") {
    // No ownership source available — skip (unit-test contexts only).
    return;
  }

  let transaction: { userId?: string | null } | null | undefined;
  try {
    transaction = await model.findById(transactionId, userId);
  } catch {
    throw forbidden("Unable to verify transaction ownership");
  }

  if (!transaction) {
    throw forbidden(
      `Not authorized to subscribe to transaction ${transactionId}`,
    );
  }
}

/**
 * Asserts the subscriber owns the dispute by checking ownership of the
 * dispute's underlying transaction.
 */
export async function assertDisputeAccess(
  context: SubscriptionAuthContext,
  disputeId: string,
): Promise<void> {
  const userId = subscriberId(context);
  if (!userId) {
    throw forbidden("UNAUTHENTICATED: valid authToken required");
  }

  const service = context?.disputeService;
  if (!service || typeof service.getDispute !== "function") {
    return;
  }

  let dispute: { transactionId?: string } | null | undefined;
  try {
    dispute = await service.getDispute(disputeId);
  } catch {
    throw forbidden(`Not authorized to subscribe to dispute ${disputeId}`);
  }

  if (!dispute?.transactionId) {
    throw forbidden(`Not authorized to subscribe to dispute ${disputeId}`);
  }

  await assertTransactionAccess(context, dispute.transactionId);
}

/** Asserts the subscriber owns the bulk import job. */
export async function assertBulkImportJobAccess(
  context: SubscriptionAuthContext,
  jobId: string,
): Promise<void> {
  const userId = subscriberId(context);
  if (!userId) {
    throw forbidden("UNAUTHENTICATED: valid authToken required");
  }

  const getJob = context?.getBulkImportJob;
  if (typeof getJob !== "function") {
    return;
  }

  let job: { userId?: string | null } | null | undefined;
  try {
    job = await getJob(jobId);
  } catch {
    throw forbidden(`Not authorized to subscribe to job ${jobId}`);
  }

  // If the job carries an owner, it must match. Jobs without an owner field
  // are not attributable to a user and are left to the id-scoped filter.
  if (job && job.userId && job.userId !== userId) {
    throw forbidden(`Not authorized to subscribe to job ${jobId}`);
  }
}
