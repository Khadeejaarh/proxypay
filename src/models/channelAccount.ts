/**
 * Channel Account Model
 *
 * Database-backed persistence layer for Stellar channel accounts.
 * Handles encrypted key storage, atomic acquisition via row-level locking,
 * and stale-lock recovery.
 *
 * Issue: #843
 * Issue: #792 — signing secrets are kept in a managed secret store; only a
 * secret reference is persisted. Provisioning requires approval and is
 * bounded by funding limits.
 */

import { queryRead, queryWrite, pool } from "../config/database";
import {
  encryptAES,
  decryptAES,
  deriveKey,
  serializePayload,
  deserializePayload,
} from "../utils/encryption";
import { env } from "../config/env";

// Types

/** Status of a channel account in the pool */
export type ChannelAccountStatus = "idle" | "busy" | "disabled" | "funding";

/** Approval state for a channel-account provisioning request */
export type ChannelAccountApprovalStatus =
  | "pending"
  | "approved"
  | "rejected";

/** Row shape returned from the channel_accounts table */
export interface ChannelAccountRow {
  id: string;
  publicKey: string;
  /** Reference into the managed secret store (never the raw secret) */
  secretRef: string;
  status: ChannelAccountStatus;
  sequence: string; // bigint comes back as string from pg
  errorCount: number;
  lockedAt: Date | null;
  disabledAt: Date | null;
  lastUsedAt: Date | null;
  fundedAt: Date | null;
  balance: string;
  createdAt: Date;
  updatedAt: Date;
}

/** Row shape for a pending provisioning request */
export interface ChannelAccountProvisioningRow {
  id: string;
  publicKey: string;
  secretRef: string;
  requestedBy: string;
  approvedBy: string | null;
  approvalStatus: ChannelAccountApprovalStatus;
  fundingAmount: string;
  createdAt: Date;
  decidedAt: Date | null;
}

/** Options for a provisioning request */
export interface ProvisioningRequestOptions {
  /** Identity of the admin requesting provisioning (RBAC-checked upstream) */
  requestedBy: string;
  /** Amount of XLM to fund the new account with */
  fundingAmount: string;
  /** Maximum XLM allowed per provisioning request */
  maxFundingAmount?: string;
}

// Key derivation — domain-separated from PII keys

const CHANNEL_KEY_INFO = "channel-accounts";

/** Default per-request funding cap (XLM) when none is configured */
const DEFAULT_MAX_FUNDING_AMOUNT = "100";

function getChannelKey(): Buffer {
  return deriveKey(env.DB_ENCRYPTION_KEY, CHANNEL_KEY_INFO);
}

// Column mapping

const SELECT_COLUMNS = `
  id,
  public_key      AS "publicKey",
  secret_ref      AS "secretRef",
  status,
  sequence::text  AS "sequence",
  error_count     AS "errorCount",
  locked_at       AS "lockedAt",
  disabled_at     AS "disabledAt",
  last_used_at    AS "lastUsedAt",
  funded_at       AS "fundedAt",
  balance::text   AS "balance",
  created_at      AS "createdAt",
  updated_at      AS "updatedAt"
`;

const SELECT_PROVISIONING_COLUMNS = `
  id,
  public_key        AS "publicKey",
  secret_ref        AS "secretRef",
  requested_by      AS "requestedBy",
  approved_by       AS "approvedBy",
  approval_status   AS "approvalStatus",
  funding_amount::text AS "fundingAmount",
  created_at        AS "createdAt",
  decided_at        AS "decidedAt"
`;

// Model

export class ChannelAccountModel {
  // Provisioning approval workflow

  /**
   * Record a provisioning request. The signing secret is written to the
   * managed secret store and only its reference is persisted here. The
   * request stays `pending` until an admin approves it.
   */
  async requestProvisioning(
    publicKey: string,
    secretRef: string,
    opts: ProvisioningRequestOptions,
  ): Promise<ChannelAccountProvisioningRow> {
    const maxFunding = opts.maxFundingAmount ?? DEFAULT_MAX_FUNDING_AMOUNT;
    if (Number(opts.fundingAmount) > Number(maxFunding)) {
      throw new Error(
        `Funding amount ${opts.fundingAmount} exceeds limit ${maxFunding}`,
      );
    }

    const result = await queryWrite<ChannelAccountProvisioningRow>(
      `INSERT INTO channel_account_provisioning
         (public_key, secret_ref, requested_by, approval_status, funding_amount)
       VALUES ($1, $2, $3, 'pending', $4)
       RETURNING ${SELECT_PROVISIONING_COLUMNS}`,
      [publicKey, secretRef, opts.requestedBy, opts.fundingAmount],
    );

    return result.rows[0];
  }

  /**
   * Approve a pending provisioning request. Only an approver distinct from
   * the requester may approve (separation of duties).
   */
  async approveProvisioning(
    id: string,
    approvedBy: string,
  ): Promise<ChannelAccountProvisioningRow | null> {
    const result = await queryWrite<ChannelAccountProvisioningRow>(
      `UPDATE channel_account_provisioning
       SET approval_status = 'approved',
           approved_by     = $2,
           decided_at      = NOW()
       WHERE id = $1
         AND approval_status = 'pending'
         AND requested_by <> $2
       RETURNING ${SELECT_PROVISIONING_COLUMNS}`,
      [id, approvedBy],
    );

    return result.rows[0] ?? null;
  }

  /**
   * Reject a pending provisioning request.
   */
  async rejectProvisioning(
    id: string,
    approvedBy: string,
  ): Promise<ChannelAccountProvisioningRow | null> {
    const result = await queryWrite<ChannelAccountProvisioningRow>(
      `UPDATE channel_account_provisioning
       SET approval_status = 'rejected',
           approved_by     = $2,
           decided_at      = NOW()
       WHERE id = $1 AND approval_status = 'pending'
       RETURNING ${SELECT_PROVISIONING_COLUMNS}`,
      [id, approvedBy],
    );

    return result.rows[0] ?? null;
  }

  // Create

  /**
   * Insert a new channel account from an approved provisioning request.
   * Persists only the secret reference — never the raw signing secret.
   */
  async create(
    publicKey: string,
    secretRef: string,
    opts: {
      balance?: string;
      sequence?: string;
      status?: ChannelAccountStatus;
    } = {},
  ): Promise<ChannelAccountRow> {
    const result = await queryWrite<ChannelAccountRow>(
      `INSERT INTO channel_accounts
         (public_key, secret_ref, balance, sequence, status)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING ${SELECT_COLUMNS}`,
      [
        publicKey,
        secretRef,
        opts.balance ?? "0",
        opts.sequence ?? "0",
        opts.status ?? "idle",
      ],
    );

    return result.rows[0];
  }

  /**
   * Resolve the signing secret for a channel account from the managed
   * secret store. Callers must never log the returned value.
   */
  async resolveSecret(secretRef: string): Promise<string> {
    const key = getChannelKey();
    const stored = await queryRead<{ encryptedKey: string }>(
      `SELECT encrypted_key AS "encryptedKey"
       FROM channel_account_secrets WHERE secret_ref = $1`,
      [secretRef],
    );
    const row = stored.rows[0];
    if (!row) {
      throw new Error(`Secret reference not found: ${secretRef}`);
    }
    return decryptAES(deserializePayload(row.encryptedKey), key);
  }

  /**
   * Rotate the signing secret for a channel account. The new secret is
   * written to the managed secret store under a fresh reference and the
   * account row is repointed atomically.
   */
  async rotateSecret(
    id: string,
    newSecret: string,
  ): Promise<ChannelAccountRow | null> {
    const key = getChannelKey();
    const newRef = `channel/${id}/${Date.now()}`;
    const encryptedKey = serializePayload(encryptAES(newSecret, key));

    await queryWrite(
      `INSERT INTO channel_account_secrets (secret_ref, encrypted_key)
       VALUES ($1, $2)`,
      [newRef, encryptedKey],
    );

    const result = await queryWrite<ChannelAccountRow>(
      `UPDATE channel_accounts
       SET secret_ref = $2
       WHERE id = $1
       RETURNING ${SELECT_COLUMNS}`,
      [id, newRef],
    );

    return result.rows[0] ?? null;
  }

  // Acquire / Release  (hot path — row-level locking)

  /**
   * Atomically acquire an idle channel account.
   *
   * Uses `FOR UPDATE SKIP LOCKED` so concurrent callers never contend on the
   * same row — each gets a different idle account or NULL if none available.
   */
  async acquireIdle(): Promise<ChannelAccountRow | null> {
    const result = await queryWrite<ChannelAccountRow>(
      `UPDATE channel_accounts
       SET status     = 'busy',
           locked_at  = NOW(),
           last_used_at = NOW()
       WHERE id = (
         SELECT id FROM channel_accounts
         WHERE status = 'idle'
         ORDER BY last_used_at ASC NULLS FIRST, error_count ASC
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING ${SELECT_COLUMNS}`,
    );

    return result.rows[0] ?? null;
  }

  /**
   * Release a channel account after transaction completion.
   *
   * On success: resets to idle, clears error count, updates sequence.
   * On failure: increments error count; disables if threshold exceeded.
   */
  async release(
    id: string,
    success: boolean,
    opts: { newSequence?: string; maxErrors?: number } = {},
  ): Promise<ChannelAccountRow | null> {
    const maxErrors = opts.maxErrors ?? 5;

    if (success) {
      const params: unknown[] = [id];
      let seqClause = "";
      if (opts.newSequence !== undefined) {
        seqClause = ", sequence = $2";
        params.push(opts.newSequence);
      }

      const result = await queryWrite<ChannelAccountRow>(
        `UPDATE channel_accounts
         SET status      = 'idle',
             locked_at   = NULL,
             error_count = 0
             ${seqClause}
         WHERE id = $1
         RETURNING ${SELECT_COLUMNS}`,
        params,
      );
      return result.rows[0] ?? null;
    }

    // Failure path: increment error_count, conditionally disable
    const result = await queryWrite<ChannelAccountRow>(
      `UPDATE channel_accounts
       SET status      = CASE WHEN error_count + 1 >= $2 THEN 'disabled' ELSE 'idle' END,
           locked_at   = NULL,
           disabled_at = CASE WHEN error_count + 1 >= $2 THEN NOW() ELSE disabled_at END,
           error_count = error_count + 1
       WHERE id = $1
       RETURNING ${SELECT_COLUMNS}`,
      [id, maxErrors],
    );

    return result.rows[0] ?? null;
  }

  // Recovery

  /**
   * Recover channel accounts stuck in 'busy' state past a timeout threshold.
   * Returns the number of recovered accounts.
   */
  async recoverStale(timeoutMs: number): Promise<number> {
    const result = await queryWrite(
      `UPDATE channel_accounts
       SET status    = 'idle',
           locked_at = NULL,
           error_count = error_count + 1
       WHERE status = 'busy'
         AND locked_at < NOW() - ($1 || ' milliseconds')::INTERVAL`,
      [timeoutMs],
    );

    return result.rowCount ?? 0;
  }

  /**
   * Re-enable disabled accounts that have been disabled for longer than
   * the recovery period.
   */
  async recoverDisabled(recoveryMs: number): Promise<number> {
    const result = await queryWrite(
      `UPDATE channel_accounts
       SET status      = 'idle',
           disabled_at = NULL,
           error_count = 0
       WHERE status = 'disabled'
         AND disabled_at < NOW() - ($1 || ' milliseconds')::INTERVAL`,
      [recoveryMs],
    );

    return result.rowCount ?? 0;
  }

  // Queries

  async findAll(): Promise<ChannelAccountRow[]> {
    const result = await queryRead<ChannelAccountRow>(
      `SELECT ${SELECT_COLUMNS} FROM channel_accounts ORDER BY created_at ASC`,
    );
    return result.rows;
  }

  async findById(id: string): Promise<ChannelAccountRow | null> {
    const result = await queryRead<ChannelAccountRow>(
      `SELECT ${SELECT_COLUMNS} FROM channel_accounts WHERE id = $1`,
      [id],
    );
    return result.rows[0] ?? null;
  }

  async findByPublicKey(publicKey: string): Promise<ChannelAccountRow | null> {
    const result = await queryRead<ChannelAccountRow>(
      `SELECT ${SELECT_COLUMNS} FROM channel_accounts WHERE public_key = $1`,
      [publicKey],
    );
    return result.rows[0] ?? null;
  }

  async findByStatus(
    status: ChannelAccountStatus,
  ): Promise<ChannelAccountRow[]> {
    const result = await queryRead<ChannelAccountRow>(
      `SELECT ${SELECT_COLUMNS} FROM channel_accounts WHERE status = $1 ORDER BY last_used_at ASC`,
      [status],
    );
    return result.rows;
  }

  async countByStatus(status: ChannelAccountStatus): Promise<number> {
    const result = await queryRead<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM channel_accounts WHERE status = $1`,
      [status],
    );
    return parseInt(result.rows[0]?.count ?? "0", 10);
  }

  async countAll(): Promise<number> {
    const result = await queryRead<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM channel_accounts`,
    );
    return parseInt(result.rows[0]?.count ?? "0", 10);
  }

  // Updates

  async updateSequence(id: string, sequence: string): Promise<void> {
    await queryWrite(
      `UPDATE channel_accounts SET sequence = $2 WHERE id = $1`,
      [id, sequence],
    );
  }

  async updateBalance(id: string, balance: string): Promise<void> {
    await queryWrite(
      `UPDATE channel_accounts SET balance = $2, funded_at = NOW() WHERE id = $1`,
      [id, balance],
    );
  }

  async disable(id: string): Promise<void> {
    await queryWrite(
      `UPDATE channel_accounts
       SET status = 'disabled', disabled_at = NOW()
       WHERE id = $1`,
      [id],
    );
  }
}
