/**
 * GDPR Data Retention Policy Service
 *
 * Retention periods are configured per data type in the `retention_policies`
 * table (seeded by migration 20260730_create_retention_policies). Environment
 * variables provide the fallback used before the table is populated or when it
 * is unavailable.
 *
 * Legal holds (`legal_holds`) and mandatory financial retention categories
 * (`retention_policy_categories`) are evaluated before any deletion so that
 * records subject to a hold or a mandatory retention requirement are never
 * purged. Every purge run is recorded in `retention_purge_audit` together with
 * the legal basis and outcome so compliance can evidence enforcement.
 */

import { pool } from "../config/database";

export const RETENTION_DATA_TYPES = ["transactions", "logs", "pii"] as const;

export type RetentionDataType = (typeof RETENTION_DATA_TYPES)[number];

export interface RetentionPolicy {
  dataType: RetentionDataType;
  retentionDays: number;
  enabled: boolean;
}

export interface LegalHold {
  id: number;
  dataType: RetentionDataType;
  subjectRef: string | null;
  reason: string;
  active: boolean;
  placedAt: Date;
  releasedAt: Date | null;
}

export interface RetentionCategory {
  dataType: RetentionDataType;
  category: string;
  mandatory: boolean;
  legalBasis: string;
}

export interface PurgeResult {
  dataType: RetentionDataType;
  retentionDays: number;
  cutoff: Date;
  recordsAffected: number;
  recordsEligible: number;
  recordsHeld: number;
  legalBasis: string;
  outcome: "success" | "failed" | "skipped";
  error?: string;
}

const DEFAULT_RETENTION_DAYS: Record<RetentionDataType, number> = {
  transactions: 2555, // 7 years
  logs: 365,
  pii: 2555,
};

const RETENTION_ENV_VARS: Record<RetentionDataType, string> = {
  transactions: "RETENTION_TRANSACTIONS_DAYS",
  logs: "RETENTION_LOGS_DAYS",
  pii: "RETENTION_PII_DAYS",
};

const DEFAULT_LEGAL_BASIS: Record<RetentionDataType, string> = {
  transactions: "legal_obligation:financial_records",
  logs: "legitimate_interest:security_audit",
  pii: "legal_obligation:financial_records",
};

function defaultPolicy(dataType: RetentionDataType): RetentionPolicy {
  const configured = parseInt(
    process.env[RETENTION_ENV_VARS[dataType]] || "",
    10,
  );

  return {
    dataType,
    retentionDays: Number.isFinite(configured) && configured > 0
      ? configured
      : DEFAULT_RETENTION_DAYS[dataType],
    enabled: true,
  };
}

function cutoffFor(retentionDays: number): Date {
  return new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
}

/**
 * Purges a single data type. Each statement is written to be idempotent so a
 * re-run reports zero affected records rather than re-purging. Records under an
 * active legal hold or a mandatory financial retention category are excluded
 * from the eligible set before deletion.
 */
async function purgeDataType(
  dataType: RetentionDataType,
  cutoff: Date,
): Promise<number> {
  switch (dataType) {
    case "transactions": {
      // Hard-delete: only terminal transactions are eligible and never those
      // covered by an active legal hold or mandatory financial retention.
      const result = await pool.query(
        `DELETE FROM transactions t
         WHERE t.status IN ('completed', 'failed', 'cancelled')
           AND t.created_at < $1
           AND NOT EXISTS (
             SELECT 1 FROM legal_holds h
             WHERE h.data_type = 'transactions'
               AND h.active = true
               AND (h.subject_ref IS NULL OR h.subject_ref = t.id::text)
           )
           AND NOT EXISTS (
             SELECT 1 FROM retention_policy_categories c
             WHERE c.data_type = 'transactions'
               AND c.mandatory = true
           )`,
        [cutoff],
      );
      return result?.rowCount ?? 0;
    }
    case "logs": {
      const result = await pool.query(
        `DELETE FROM audit_logs l
         WHERE l.created_at < $1
           AND NOT EXISTS (
             SELECT 1 FROM legal_holds h
             WHERE h.data_type = 'logs'
               AND h.active = true
               AND (h.subject_ref IS NULL OR h.subject_ref = l.id::text)
           )
           AND NOT EXISTS (
             SELECT 1 FROM retention_policy_categories c
             WHERE c.data_type = 'logs'
               AND c.mandatory = true
           )`,
        [cutoff],
      );
      return result?.rowCount ?? 0;
    }
    case "pii": {
      // Soft-delete: strip PII from deactivated accounts, keep the record so
      // financial history stays referentially intact. Accounts under an active
      // legal hold or mandatory financial retention are left untouched.
      const result = await pool.query(
        `UPDATE users u
         SET first_name = NULL,
             last_name = NULL,
             address = NULL,
             date_of_birth = NULL,
             id_number = NULL
         WHERE u.is_active = false
           AND u.deactivated_at < $1
           AND (u.first_name IS NOT NULL
                OR u.last_name IS NOT NULL
                OR u.address IS NOT NULL
                OR u.date_of_birth IS NOT NULL
                OR u.id_number IS NOT NULL)
           AND NOT EXISTS (
             SELECT 1 FROM legal_holds h
             WHERE h.data_type = 'pii'
               AND h.active = true
               AND (h.subject_ref IS NULL OR h.subject_ref = u.id::text)
           )
           AND NOT EXISTS (
             SELECT 1 FROM retention_policy_categories c
             WHERE c.data_type = 'pii'
               AND c.mandatory = true
           )`,
        [cutoff],
      );
      return result?.rowCount ?? 0;
    }
  }
}

/**
 * Counts records that would be purged for a data type, excluding those under an
 * active legal hold or a mandatory financial retention category. Used to
 * calculate the eligible set before deletion.
 */
async function countEligible(
  dataType: RetentionDataType,
  cutoff: Date,
): Promise<{ eligible: number; held: number }> {
  switch (dataType) {
    case "transactions": {
      const result = await pool.query(
        `SELECT
           COUNT(*) FILTER (WHERE NOT held) AS eligible,
           COUNT(*) FILTER (WHERE held) AS held
         FROM (
           SELECT t.id,
             EXISTS (
               SELECT 1 FROM legal_holds h
               WHERE h.data_type = 'transactions'
                 AND h.active = true
                 AND (h.subject_ref IS NULL OR h.subject_ref = t.id::text)
             ) OR EXISTS (
               SELECT 1 FROM retention_policy_categories c
               WHERE c.data_type = 'transactions' AND c.mandatory = true
             ) AS held
           FROM transactions t
           WHERE t.status IN ('completed', 'failed', 'cancelled')
             AND t.created_at < $1
         ) sub`,
        [cutoff],
      );
      return {
        eligible: Number(result.rows[0]?.eligible ?? 0),
        held: Number(result.rows[0]?.held ?? 0),
      };
    }
    case "logs": {
      const result = await pool.query(
        `SELECT
           COUNT(*) FILTER (WHERE NOT held) AS eligible,
           COUNT(*) FILTER (WHERE held) AS held
         FROM (
           SELECT l.id,
             EXISTS (
               SELECT 1 FROM legal_holds h
               WHERE h.data_type = 'logs'
                 AND h.active = true
                 AND (h.subject_ref IS NULL OR h.subject_ref = l.id::text)
             ) OR EXISTS (
               SELECT 1 FROM retention_policy_categories c
               WHERE c.data_type = 'logs' AND c.mandatory = true
             ) AS held
           FROM audit_logs l
           WHERE l.created_at < $1
         ) sub`,
        [cutoff],
      );
      return {
        eligible: Number(result.rows[0]?.eligible ?? 0),
        held: Number(result.rows[0]?.held ?? 0),
      };
    }
    case "pii": {
      const result = await pool.query(
        `SELECT
           COUNT(*) FILTER (WHERE NOT held) AS eligible,
           COUNT(*) FILTER (WHERE held) AS held
         FROM (
           SELECT u.id,
             EXISTS (
               SELECT 1 FROM legal_holds h
               WHERE h.data_type = 'pii'
                 AND h.active = true
                 AND (h.subject_ref IS NULL OR h.subject_ref = u.id::text)
             ) OR EXISTS (
               SELECT 1 FROM retention_policy_categories c
               WHERE c.data_type = 'pii' AND c.mandatory = true
             ) AS held
           FROM users u
           WHERE u.is_active = false
             AND u.deactivated_at < $1
             AND (u.first_name IS NOT NULL
                  OR u.last_name IS NOT NULL
                  OR u.address IS NOT NULL
                  OR u.date_of_birth IS NOT NULL
                  OR u.id_number IS NOT NULL)
         ) sub`,
        [cutoff],
      );
      return {
        eligible: Number(result.rows[0]?.eligible ?? 0),
        held: Number(result.rows[0]?.held ?? 0),
      };
    }
  }
}

export class RetentionPolicyService {
  /** Returns the effective policy for every known data type. */
  async getPolicies(): Promise<RetentionPolicy[]> {
    const defaults = RETENTION_DATA_TYPES.map(defaultPolicy);

    try {
      const result = await pool.query(
        `SELECT data_type, retention_days, enabled FROM retention_policies`,
      );

      return defaults.map((policy) => {
        const row = result.rows.find(
          (r: { data_type: string }) => r.data_type === policy.dataType,
        );
        if (!row) return policy;
        return {
          dataType: policy.dataType,
          retentionDays: Number(row.retention_days),
          enabled: Boolean(row.enabled),
        };
      });
    } catch (err) {
      console.warn(
        "[retention] Falling back to default policies:",
        err instanceof Error ? err.message : err,
      );
      return defaults;
    }
  }

  /** Updates (or inserts) the policy for a single data type. */
  async setPolicy(
    dataType: RetentionDataType,
    retentionDays: number,
    enabled = true,
  ): Promise<void> {
    if (!Number.isInteger(retentionDays) || retentionDays <= 0) {
      throw new Error("retentionDays must be a positive integer");
    }

    await pool.query(
      `INSERT INTO retention_policies (data_type, retention_days, enabled, updated_at)
       VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
       ON CONFLICT (data_type) DO UPDATE
         SET retention_days = EXCLUDED.retention_days,
             enabled = EXCLUDED.enabled,
             updated_at = CURRENT_TIMESTAMP`,
      [dataType, retentionDays, enabled],
    );
  }

  /** Returns the active legal holds, optionally filtered by data type. */
  async getActiveLegalHolds(
    dataType?: RetentionDataType,
  ): Promise<LegalHold[]> {
    const result = await pool.query(
      `SELECT id, data_type, subject_ref, reason, active, placed_at, released_at
       FROM legal_holds
       WHERE active = true
         AND ($1::text IS NULL OR data_type = $1)
       ORDER BY placed_at DESC`,
      [dataType ?? null],
    );
    return result.rows.map((row: Record<string, unknown>) => ({
      id: Number(row.id),
      dataType: row.data_type as RetentionDataType,
      subjectRef: (row.subject_ref as string | null) ?? null,
      reason: String(row.reason),
      active: Boolean(row.active),
      placedAt: new Date(row.placed_at as string),
      releasedAt: row.released_at ? new Date(row.released_at as string) : null,
    }));
  }

  /** Places a legal hold on a data type (optionally a single subject). */
  async placeLegalHold(
    dataType: RetentionDataType,
    reason: string,
    subjectRef: string | null = null,
  ): Promise<void> {
    await pool.query(
      `INSERT INTO legal_holds (data_type, subject_ref, reason, active, placed_at)
       VALUES ($1, $2, $3, true, CURRENT_TIMESTAMP)`,
      [dataType, subjectRef, reason],
    );
  }

  /** Releases an active legal hold by id. */
  async releaseLegalHold(id: number): Promise<void> {
    await pool.query(
      `UPDATE legal_holds
       SET active = false, released_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND active = true`,
      [id],
    );
  }

  /** Returns the retention categories (including mandatory ones). */
  async getCategories(): Promise<RetentionCategory[]> {
    const result = await pool.query(
      `SELECT data_type, category, mandatory, legal_basis
       FROM retention_policy_categories`,
    );
    return result.rows.map((row: Record<string, unknown>) => ({
      dataType: row.data_type as RetentionDataType,
      category: String(row.category),
      mandatory: Boolean(row.mandatory),
      legalBasis: String(row.legal_basis),
    }));
  }

  /**
   * Resolves the legal basis for a data type: the mandatory category's basis
   * when one exists, otherwise the default basis for the data type.
   */
  private async resolveLegalBasis(
    dataType: RetentionDataType,
  ): Promise<string> {
    try {
      const result = await pool.query(
        `SELECT legal_basis FROM retention_policy_categories
         WHERE data_type = $1 AND mandatory = true
         ORDER BY category
         LIMIT 1`,
        [dataType],
      );
      const basis = result.rows[0]?.legal_basis;
      return basis ? String(basis) : DEFAULT_LEGAL_BASIS[dataType];
    } catch (err) {
      console.warn(
        `[retention] Falling back to default legal basis for ${dataType}:`,
        err instanceof Error ? err.message : err,
      );
      return DEFAULT_LEGAL_BASIS[dataType];
    }
  }

  /** Enforces every enabled policy, recording each outcome in the audit log. */
  async enforceAll(): Promise<PurgeResult[]> {
    const policies = await this.getPolicies();
    const results: PurgeResult[] = [];

    for (const policy of policies) {
      const cutoff = cutoffFor(policy.retentionDays);
      const legalBasis = await this.resolveLegalBasis(policy.dataType);

      if (!policy.enabled) {
        results.push({
          dataType: policy.dataType,
          retentionDays: policy.retentionDays,
          cutoff,
          recordsAffected: 0,
          recordsEligible: 0,
          recordsHeld: 0,
          legalBasis,
          outcome: "skipped",
        });
        continue;
      }

      let result: PurgeResult;
      try {
        const { eligible, held } = await countEligible(
          policy.dataType,
          cutoff,
        );
        const recordsAffected = await purgeDataType(policy.dataType, cutoff);
        result = {
          dataType: policy.dataType,
          retentionDays: policy.retentionDays,
          cutoff,
          recordsAffected,
          recordsEligible: eligible,
          recordsHeld: held,
          legalBasis,
          outcome: "success",
        };
      } catch (err) {
        result = {
          dataType: policy.dataType,
          retentionDays: policy.retentionDays,
          cutoff,
          recordsAffected: 0,
          recordsEligible: 0,
          recordsHeld: 0,
          legalBasis,
          outcome: "failed",
          error: err instanceof Error ? err.message : String(err),
        };
      }

      await this.recordPurge(result);
      results.push(result);
    }

    return results;
  }

  /** Returns the most recent purge audit entries, newest first. */
  async getPurgeAudit(limit = 50): Promise<unknown[]> {
    const result = await pool.query(
      `SELECT id, data_type, retention_days, cutoff_at, records_affected,
              records_eligible, records_held, legal_basis, outcome, error,
              executed_at
       FROM retention_purge_audit
       ORDER BY executed_at DESC
       LIMIT $1`,
      [Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows;
  }

  private async recordPurge(result: PurgeResult): Promise<void> {
    try {
      await pool.query(
        `INSERT INTO retention_purge_audit
           (data_type, retention_days, cutoff_at, records_affected,
            records_eligible, records_held, legal_basis, outcome, error)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          result.dataType,
          result.retentionDays,
          result.cutoff,
          result.recordsAffected,
          result.recordsEligible,
          result.recordsHeld,
          result.legalBasis,
          result.outcome,
          result.error ?? null,
        ],
      );
    } catch (err) {
      console.error(
        `[retention] Failed to write purge audit for ${result.dataType}:`,
        err instanceof Error ? err.message : err,
      );
    }
  }
}

export const retentionPolicyService = new RetentionPolicyService();
