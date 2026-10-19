/**
 * Provider Reconciliation Service
 *
 * Compares local payout records against the provider's remote API to detect
 * discrepancies such as:
 *   - Status mismatches  (local says "completed", provider says "failed")
 *   - Amount mismatches  (rounding / FX differences)
 *   - Missing records    (exists locally but not remotely, or vice-versa)
 *
 * Integrators should supply their own `fetchLocalPayouts` and
 * `fetchRemotePayouts` implementations — the defaults below are stubs
 * that return demo data so the script is runnable out of the box.
 *
 * SEP-31 idempotency helpers (`submitPayoutIdempotent`,
 * `reconcileCompletionCallback`) live here so payout submission and
 * callback handling share the same persisted reference store.
 */

import axios from "axios";
import { config } from "../config/env";
import type {
  LocalPayoutRecord,
  RemotePayoutRecord,
  ReconciliationEntry,
  ReconciliationReport,
} from "../types/reconciliation";

// ─── Data-source adapters (replace with real implementations) ────────────────

/**
 * Fetch payout records from the local data store.
 *
 * Replace this stub with a real database / file query.
 */
export async function fetchLocalPayouts(): Promise<LocalPayoutRecord[]> {
  // TODO: Replace with your actual local data source (database, CSV, etc.)
  console.log("[reconciler] Fetching local payout records …");
  return [];
}

/**
 * Fetch payout records from the remote provider API.
 *
 * By default this calls `GET <BRIDGE_API_URL>/payouts` using the configured
 * API key.  Adjust the endpoint, pagination, and response mapping to match
 * your provider.
 */
export async function fetchRemotePayouts(): Promise<RemotePayoutRecord[]> {
  console.log("[reconciler] Fetching remote payout records …");

  if (!config.bridgeApiUrl) {
    console.warn(
      "[reconciler] BRIDGE_API_URL is not set — returning empty remote list."
    );
    return [];
  }

  try {
    const response = await axios.get<RemotePayoutRecord[]>(
      `${config.bridgeApiUrl}/payouts`,
      {
        headers: {
          Authorization: `Bearer ${config.bridgeApiKey}`,
          "Content-Type": "application/json",
        },
      }
    );
    return response.data;
  } catch (error: any) {
    console.error(
      "[reconciler] Failed to fetch remote payouts:",
      error.response?.data || error.message
    );
    return [];
  }
}

// ─── SEP-31 idempotent payout submission ─────────────────────────────────────

/**
 * Persisted SEP-31 transaction reference.  The `reference` is the unique
 * idempotency key that must be written *before* any external call so that
 * retries and duplicate callbacks can be reconciled against it.
 */
export interface Sep31PayoutReference {
  reference: string;
  status: "pending" | "submitted" | "completed" | "failed";
  providerPayoutId: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * In-memory reference store keyed by the unique SEP-31 reference.
 *
 * In production this should be backed by a database table with a UNIQUE
 * constraint on `reference` (e.g. `UNIQUE(reference)`), so that concurrent
 * submissions of the same reference cannot both proceed.  The Map below
 * enforces the same uniqueness invariant for the starter.
 */
const payoutReferences = new Map<string, Sep31PayoutReference>();

/**
 * Persist a unique SEP-31 transaction reference before any external call.
 *
 * Returns the existing record when the reference was already persisted
 * (idempotent), or a freshly created `pending` record otherwise.  Callers
 * MUST treat a non-`pending` existing record as "already submitted" and
 * avoid re-submitting the payout.
 */
export function persistPayoutReference(
  reference: string
): Sep31PayoutReference {
  const existing = payoutReferences.get(reference);
  if (existing) {
    return existing;
  }

  const now = new Date().toISOString();
  const record: Sep31PayoutReference = {
    reference,
    status: "pending",
    providerPayoutId: null,
    createdAt: now,
    updatedAt: now,
  };
  payoutReferences.set(reference, record);
  return record;
}

/**
 * Query the provider status API to determine whether a payout for the given
 * reference already exists.  Used after ambiguous failures (timeouts /
 * unknown responses) to avoid submitting a second payout.
 */
export async function queryProviderPayoutStatus(
  reference: string
): Promise<RemotePayoutRecord | null> {
  if (!config.bridgeApiUrl) {
    return null;
  }

  try {
    const response = await axios.get<RemotePayoutRecord>(
      `${config.bridgeApiUrl}/payouts/${encodeURIComponent(reference)}`,
      {
        headers: {
          Authorization: `Bearer ${config.bridgeApiKey}`,
          "Content-Type": "application/json",
        },
      }
    );
    return response.data;
  } catch (error: any) {
    // 404 means the provider has no record — safe to retry submission.
    if (error.response?.status === 404) {
      return null;
    }
    // Any other failure is ambiguous; surface it so the caller does not
    // blindly retry and risk a duplicate payout.
    throw error;
  }
}

/**
 * Submit a SEP-31 payout idempotently.
 *
 * 1. Persist the unique reference before any external call.
 * 2. If the reference was already submitted/completed, return the stored
 *    record instead of submitting again.
 * 3. On ambiguous failure, query the provider status API before retrying.
 */
export async function submitPayoutIdempotent(
  reference: string,
  submit: (reference: string) => Promise<RemotePayoutRecord>
): Promise<Sep31PayoutReference> {
  const record = persistPayoutReference(reference);

  // Already submitted or completed — do not submit a second payout.
  if (record.status === "submitted" || record.status === "completed") {
    return record;
  }

  try {
    const remote = await submit(reference);
    record.status = "submitted";
    record.providerPayoutId = remote.id;
    record.updatedAt = new Date().toISOString();
    payoutReferences.set(reference, record);
    return record;
  } catch (error) {
    // Ambiguous failure: check whether the provider already has the payout.
    const remote = await queryProviderPayoutStatus(reference);
    if (remote) {
      record.status = "submitted";
      record.providerPayoutId = remote.id;
      record.updatedAt = new Date().toISOString();
      payoutReferences.set(reference, record);
      return record;
    }
    throw error;
  }
}

/**
 * Reconcile a completion callback against the persisted reference.
 *
 * Duplicate or out-of-order callbacks are matched to the existing record so
 * they never create a second payout.  Returns the updated record, or `null`
 * when the callback references an unknown transaction.
 */
export function reconcileCompletionCallback(
  reference: string,
  providerPayoutId: string,
  status: "completed" | "failed"
): Sep31PayoutReference | null {
  const record = payoutReferences.get(reference);
  if (!record) {
    return null;
  }

  // Ignore callbacks for a different provider payout (out-of-order / stale).
  if (record.providerPayoutId && record.providerPayoutId !== providerPayoutId) {
    return record;
  }

  // Terminal states are final — duplicate callbacks are no-ops.
  if (record.status === "completed" || record.status === "failed") {
    return record;
  }

  record.providerPayoutId = providerPayoutId;
  record.status = status;
  record.updatedAt = new Date().toISOString();
  payoutReferences.set(reference, record);
  return record;
}

// ─── Core reconciliation logic ───────────────────────────────────────────────

/**
 * Compare a local record with its remote counterpart and produce a
 * `ReconciliationEntry` describing any discrepancy.
 */
function compareRecords(
  local: LocalPayoutRecord | null,
  remote: RemotePayoutRecord | null
): ReconciliationEntry {
  // Record exists only on one side
  if (!local) {
    return {
      payoutId: remote!.id,
      localStatus: null,
      remoteStatus: remote!.status,
      localAmount: null,
      remoteAmount: remote!.amount,
      match: false,
      discrepancy: "missing_local — record exists remotely but not locally",
    };
  }

  if (!remote) {
    return {
      payoutId: local.id,
      localStatus: local.status,
      remoteStatus: null,
      localAmount: local.amount,
      remoteAmount: null,
      match: false,
      discrepancy: "missing_remote — record exists locally but not remotely",
    };
  }

  // Both sides present — check for mismatches
  const discrepancies: string[] = [];

  if (local.status !== remote.status) {
    discrepancies.push(
      `status mismatch: local="${local.status}" remote="${remote.status}"`
    );
  }

  if (local.amount !== remote.amount) {
    discrepancies.push(
      `amount mismatch: local=${local.amount} remote=${remote.amount}`
    );
  }

  const match = discrepancies.length === 0;

  return {
    payoutId: local.id,
    localStatus: local.status,
    remoteStatus: remote.status,
    localAmount: local.amount,
    remoteAmount: remote.amount,
    match,
    discrepancy: match ? null : discrepancies.join("; "),
  };
}

/**
 * Run a full reconciliation pass:
 *
 * 1. Fetch local and remote payout lists.
 * 2. Index both by payout ID.
 * 3. Walk the union of IDs and compare each pair.
 * 4. Return an aggregate `ReconciliationReport`.
 */
export async function reconcile(): Promise<ReconciliationReport> {
  const localPayouts = await fetchLocalPayouts();
  const remotePayouts = await fetchRemotePayouts();

  // Index by ID for O(1) lookups
  const localMap = new Map(localPayouts.map((p) => [p.id, p]));
  const remoteMap = new Map(remotePayouts.map((p) => [p.id, p]));

  // Union of all payout IDs
  const allIds = new Set([...localMap.keys(), ...remoteMap.keys()]);

  const entries: ReconciliationEntry[] = [];
  let matched = 0;
  let mismatched = 0;
  let missingLocal = 0;
  let missingRemote = 0;

  for (const id of allIds) {
    const local = localMap.get(id) ?? null;
    const remote = remoteMap.get(id) ?? null;
    const entry = compareRecords(local, remote);
    entries.push(entry);

    if (entry.match) {
      matched++;
    } else if (!local) {
      missingLocal++;
    } else if (!remote) {
      missingRemote++;
    } else {
      mismatched++;
    }
  }

  return {
    reconciledAt: new Date().toISOString(),
    totalLocal: localPayouts.length,
    totalRemote: remotePayouts.length,
    matched,
    mismatched,
    missingLocal,
    missingRemote,
    entries,
  };
}
