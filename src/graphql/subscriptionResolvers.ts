import { withFilter } from "graphql-subscriptions";
import {
  SubscriptionChannels,
  transactionChannel,
  connectionLimitManager,
  type TransactionCreatedPayload,
  type TransactionUpdatedPayload,
  type DisputeCreatedPayload,
  type DisputeUpdatedPayload,
  type DisputeNoteAddedPayload,
  type BulkImportJobUpdatedPayload,
  type TypedPubSub,
} from "./subscriptions";
import {
  assertTransactionAccess,
  assertDisputeAccess,
  assertBulkImportJobAccess,
} from "./subscriptionAuth";

// ---------------------------------------------------------------------------
// Payload formatters
// ---------------------------------------------------------------------------

function formatTransactionPayload(
  payload: TransactionCreatedPayload | TransactionUpdatedPayload,
) {
  const base: Record<string, unknown> = {
    id: payload.id,
    referenceNumber: payload.referenceNumber,
    status: payload.status,
    retryCount: 0,
  };

  if ("type" in payload) {
    base.type = payload.type;
    base.amount = payload.amount;
    base.phoneNumber = payload.phoneNumber;
    base.provider = payload.provider;
    base.stellarAddress = payload.stellarAddress;
    base.tags = payload.tags;
    base.createdAt = payload.createdAt;
  }

  if ("updatedAt" in payload) base.updatedAt = payload.updatedAt;
  if ("jobProgress" in payload) base.jobProgress = payload.jobProgress;

  return base;
}

function formatDisputePayload(
  payload: DisputeCreatedPayload | DisputeUpdatedPayload,
) {
  const base: Record<string, unknown> = {
    id: payload.id,
    status: payload.status,
    notes: [],
  };

  if ("transactionId" in payload) {
    base.transactionId = payload.transactionId;
    base.reason = payload.reason;
    base.reportedBy = payload.reportedBy;
    base.createdAt = payload.createdAt;
  }

  if ("assignedTo" in payload) {
    base.assignedTo = payload.assignedTo;
    base.resolution = payload.resolution;
    base.updatedAt = payload.updatedAt;
  }

  return base;
}

function formatDisputeNotePayload(payload: DisputeNoteAddedPayload) {
  return {
    id: payload.id,
    disputeId: payload.disputeId,
    author: payload.author,
    note: payload.note,
    createdAt: payload.createdAt,
  };
}

function formatBulkImportJobPayload(payload: BulkImportJobUpdatedPayload) {
  return {
    jobId: payload.jobId,
    status: payload.status,
    progress: payload.progress,
    errors: payload.errors,
    createdAt: new Date().toISOString(),
    completedAt: payload.completedAt,
  };
}

// ---------------------------------------------------------------------------
// Subscription resolvers factory
// ---------------------------------------------------------------------------

/**
 * Wraps a raw AsyncIterableIterator so that the per-user connection slot is
 * released automatically when the subscription ends (either via return() or
 * throw()).  This ensures the count is always decremented even if the client
 * disconnects without an explicit unsubscribe.
 */
function withConnectionRelease<T>(
  iterator: AsyncIterableIterator<T>,
  release: () => void,
): AsyncIterableIterator<T> {
  return {
    [Symbol.asyncIterator]() { return this; },
    async next() {
      try {
        return await iterator.next();
      } catch (err) {
        release();
        throw err;
      }
    },
    async return(value?: any) {
      release();
      return iterator.return ? iterator.return(value) : { value, done: true };
    },
    async throw(err?: any) {
      release();
      return iterator.throw ? iterator.throw(err) : Promise.reject(err);
    },
  };
}

export function createSubscriptionResolvers(pubsub: TypedPubSub) {
  return {
    Subscription: {
      // ── transactionUpdated ──────────────────────────────────────────────
      // Subscribes to a per-transaction Redis channel so only the relevant
      // connection receives the event — no server-side filtering needed.
      transactionUpdated: {
        subscribe: async (
          _parent: unknown,
          args: { id: string },
          context: any,
        ) => {
          // Reject unauthenticated WS connections
          if (!context?.auth?.authenticated) {
            throw new Error("UNAUTHENTICATED: valid authToken required");
          }
          // Per-subscription ownership check (issue #814): an id-scoped
          // subscription requires the subscriber to own the transaction.
          if (args.id) {
            await assertTransactionAccess(context, args.id);
          }
          // Enforce per-user connection limit (#627)
          const release = connectionLimitManager.acquire(context.auth.subject ?? context.auth.userId ?? "anonymous");
          // Subscribe to the per-transaction channel
          const channel = args.id
            ? transactionChannel(args.id)
            : SubscriptionChannels.TRANSACTION_UPDATED;
          const iterator = pubsub.asyncIterator<TransactionUpdatedPayload>(channel);
          return withConnectionRelease(iterator, release);
        },
        resolve: (payload: TransactionUpdatedPayload) =>
          formatTransactionPayload(payload),
      },

      // ── transactionCreated ──────────────────────────────────────────────
      transactionCreated: {
        subscribe: (_parent: unknown, _args: unknown, context: any) => {
          if (!context?.auth?.authenticated) {
            throw new Error("UNAUTHENTICATED: valid authToken required");
          }
          const release = connectionLimitManager.acquire(context.auth.subject ?? context.auth.userId ?? "anonymous");
          const iterator = pubsub.asyncIterator<TransactionCreatedPayload>(
            SubscriptionChannels.TRANSACTION_CREATED,
          );
          return withConnectionRelease(iterator, release);
        },
        resolve: (payload: TransactionCreatedPayload) =>
          formatTransactionPayload(payload),
      },

      // ── transactionCompleted ────────────────────────────────────────────
      transactionCompleted: {
        subscribe: (_parent: unknown, _args: unknown, context: any) => {
          if (!context?.auth?.authenticated) {
            throw new Error("UNAUTHENTICATED: valid authToken required");
          }
          const release = connectionLimitManager.acquire(context.auth.subject ?? context.auth.userId ?? "anonymous");
          const iterator = pubsub.asyncIterator<TransactionUpdatedPayload>(
            SubscriptionChannels.TRANSACTION_COMPLETED,
          );
          return withConnectionRelease(iterator, release);
        },
        resolve: (payload: TransactionUpdatedPayload) =>
          formatTransactionPayload(payload),
      },

      // ── transactionFailed ───────────────────────────────────────────────
      transactionFailed: {
        subscribe: (_parent: unknown, _args: unknown, context: any) => {
          if (!context?.auth?.authenticated) {
            throw new Error("UNAUTHENTICATED: valid authToken required");
          }
          const release = connectionLimitManager.acquire(context.auth.subject ?? context.auth.userId ?? "anonymous");
          const iterator = pubsub.asyncIterator<TransactionUpdatedPayload>(
            SubscriptionChannels.TRANSACTION_FAILED,
          );
          return withConnectionRelease(iterator, release);
        },
        resolve: (payload: TransactionUpdatedPayload) =>
          formatTransactionPayload(payload),
      },

      // ── disputeCreated ──────────────────────────────────────────────────
      disputeCreated: {
        subscribe: (_parent: unknown, _args: unknown, context: any) => {
          if (!context?.auth?.authenticated) {
            throw new Error("UNAUTHENTICATED: valid authToken required");
          }
          const release = connectionLimitManager.acquire(context.auth.subject ?? context.auth.userId ?? "anonymous");
          const iterator = pubsub.asyncIterator<DisputeCreatedPayload>(
            SubscriptionChannels.DISPUTE_CREATED,
          );
          return withConnectionRelease(iterator, release);
        },
        resolve: (payload: DisputeCreatedPayload) =>
          formatDisputePayload(payload),
      },

      // ── disputeUpdated ──────────────────────────────────────────────────
      disputeUpdated: {
        subscribe: withFilter(
          async (_parent: unknown, args: { id?: string }, context: any) => {
            if (!context?.auth?.authenticated) {
              throw new Error("UNAUTHENTICATED: valid authToken required");
            }
            // Per-subscription ownership check (issue #814)
            if (args?.id) {
              await assertDisputeAccess(context, args.id);
            }
            const release = connectionLimitManager.acquire(context.auth.subject ?? context.auth.userId ?? "anonymous");
            const iterator = pubsub.asyncIterator<DisputeUpdatedPayload>(
              SubscriptionChannels.DISPUTE_UPDATED,
            );
            return withConnectionRelease(iterator, release);
          },
          (payload: any, variables: any) => {
            if (!variables?.id) return true;
            return payload?.id === variables.id;
          },
        ),
        resolve: (payload: DisputeUpdatedPayload) =>
          formatDisputePayload(payload),
      },

      // ── disputeNoteAdded ────────────────────────────────────────────────
      disputeNoteAdded: {
        subscribe: withFilter(
          async (
            _parent: unknown,
            args: { disputeId?: string },
            context: any,
          ) => {
            if (!context?.auth?.authenticated) {
              throw new Error("UNAUTHENTICATED: valid authToken required");
            }
            // Per-subscription ownership check (issue #814)
            if (args?.disputeId) {
              await assertDisputeAccess(context, args.disputeId);
            }
            const release = connectionLimitManager.acquire(context.auth.subject ?? context.auth.userId ?? "anonymous");
            const iterator = pubsub.asyncIterator<DisputeNoteAddedPayload>(
              SubscriptionChannels.DISPUTE_NOTE_ADDED,
            );
            return withConnectionRelease(iterator, release);
          },
          (payload: any, variables: any) => {
            if (!variables?.disputeId) return true;
            return payload?.disputeId === variables.disputeId;
          },
        ),
        resolve: (payload: DisputeNoteAddedPayload) =>
          formatDisputeNotePayload(payload),
      },

      // ── bulkImportJobUpdated ────────────────────────────────────────────
      bulkImportJobUpdated: {
        subscribe: withFilter(
          async (
            _parent: unknown,
            args: { jobId?: string },
            context: any,
          ) => {
            if (!context?.auth?.authenticated) {
              throw new Error("UNAUTHENTICATED: valid authToken required");
            }
            // Per-subscription ownership check (issue #814)
            if (args?.jobId) {
              await assertBulkImportJobAccess(context, args.jobId);
            }
            const release = connectionLimitManager.acquire(context.auth.subject ?? context.auth.userId ?? "anonymous");
            const iterator = pubsub.asyncIterator<BulkImportJobUpdatedPayload>(
              SubscriptionChannels.BULK_IMPORT_JOB_UPDATED,
            );
            return withConnectionRelease(iterator, release);
          },
          (payload: any, variables: any) =>
            payload?.jobId === variables.jobId,
        ),
        resolve: (payload: BulkImportJobUpdatedPayload) =>
          formatBulkImportJobPayload(payload),
      },
    },
  };
}
