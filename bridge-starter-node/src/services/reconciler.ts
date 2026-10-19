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
 */

import axios from "axios";
import { config } from "../config/env";
import type {
  LocalPayoutRecord,
  RemotePayoutRecord,
  ReconciliationEntry,
  ReconciliationReport,
} from "../types/reconciliation";

// ─── Transaction / consistency boundary ──────────────────────────────────────

/**
 * Minimal transaction client contract.
 *
 * Callers that already hold an open transaction (or a primary-routed
 * connection) can pass it in so that reads stay inside the caller's
 * transaction and consistency boundary instead of being routed to a
 * possibly-lagging replica.
 */
export interface TransactionClient {
  /** Execute a query against this client's connection. */
  query<T = unknown>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

/**
 * Options controlling where reads are served from.
 *
 * `client` pins reads to the caller's transaction. `primary` forces
 * read-after-write operations onto the primary so replica routing cannot
 * serve stale data.
 */
export interface ReadOptions {
  client?: TransactionClient;
  primary?: boolean;
}

// ─── Data-source adapters (replace with real implementations) ────────────────

/**
 * Fetch payout records from the local data store.
 *
 * Replace this stub with a real database / file query. When `options.client`
 * is supplied the read must run on that client so it observes writes made
 * earlier in the same transaction. When `options.primary` is set the read
 * must be routed to the primary (read-after-write).
 */
export async function fetchLocalPayouts(
  options: ReadOptions = {}
): Promise<LocalPayoutRecord[]> {
  // TODO: Replace with your actual local data source (database, CSV, etc.)
  if (options.client) {
    // Read inside the caller's transaction boundary.
    const { rows } = await options.client.query<LocalPayoutRecord>(
      "SELECT id, status, amount FROM payouts"
    );
    return rows;
  }

  console.log(
    `[reconciler] Fetching local payout records … (primary=${!!options.primary})`
  );
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
 *
 * Reconciliation reads local state that may have just been written, so the
 * local read is pinned to the primary (read-after-write) unless the caller
 * supplies an explicit transaction client.
 */
export async function reconcile(
  options: ReadOptions = {}
): Promise<ReconciliationReport> {
  const localPayouts = await fetchLocalPayouts({
    client: options.client,
    primary: options.client ? options.primary : true,
  });
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
