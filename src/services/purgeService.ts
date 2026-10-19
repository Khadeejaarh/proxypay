import { Pool, PoolClient } from 'pg';
import { logger } from '../utils/logger';

export type RetentionCategory =
  | 'standard'
  | 'financial'
  | 'legal_hold'
  | 'regulatory';

export interface RetentionPolicy {
  category: RetentionCategory;
  /** Minimum retention window in days. Records younger than this are ineligible. */
  retentionDays: number;
  /** When true, records in this category must never be purged. */
  mandatory: boolean;
}

export interface LegalHold {
  id: string;
  subjectType: string;
  subjectId: string;
  reason: string;
  active: boolean;
  createdAt: Date;
  releasedAt: Date | null;
}

export interface PurgeCandidate {
  id: string;
  subjectType: string;
  subjectId: string;
  createdAt: Date;
  retentionCategory: RetentionCategory;
}

export interface PurgeEligibility {
  eligible: PurgeCandidate[];
  excluded: Array<{
    candidate: PurgeCandidate;
    reason: 'legal_hold' | 'mandatory_retention' | 'within_retention_window';
  }>;
}

export interface PurgeBatchOutcome {
  batchId: string;
  legalBasis: string;
  eligibleCount: number;
  excludedCount: number;
  deletedCount: number;
  excludedReasons: Record<string, number>;
}

const DEFAULT_POLICIES: Record<RetentionCategory, RetentionPolicy> = {
  standard: { category: 'standard', retentionDays: 30, mandatory: false },
  financial: { category: 'financial', retentionDays: 2555, mandatory: true },
  legal_hold: { category: 'legal_hold', retentionDays: 0, mandatory: true },
  regulatory: { category: 'regulatory', retentionDays: 1825, mandatory: true },
};

/**
 * Retention policy service: resolves retention categories and legal holds so
 * purge/retention jobs can compute eligible records before deletion.
 */
export class RetentionPolicyService {
  constructor(private readonly pool: Pool) {}

  async getPolicy(category: RetentionCategory): Promise<RetentionPolicy> {
    const { rows } = await this.pool.query<{
      category: RetentionCategory;
      retention_days: number;
      mandatory: boolean;
    }>(
      'SELECT category, retention_days, mandatory FROM retention_policies WHERE category = $1',
      [category],
    );
    if (rows.length === 0) {
      return DEFAULT_POLICIES[category] ?? DEFAULT_POLICIES.standard;
    }
    const row = rows[0];
    return {
      category: row.category,
      retentionDays: row.retention_days,
      mandatory: row.mandatory,
    };
  }

  async getActiveHolds(subjectType: string, subjectIds: string[]): Promise<LegalHold[]> {
    if (subjectIds.length === 0) return [];
    const { rows } = await this.pool.query<{
      id: string;
      subject_type: string;
      subject_id: string;
      reason: string;
      active: boolean;
      created_at: Date;
      released_at: Date | null;
    }>(
      `SELECT id, subject_type, subject_id, reason, active, created_at, released_at
         FROM legal_holds
        WHERE subject_type = $1 AND active = TRUE AND subject_id = ANY($2::text[])`,
      [subjectType, subjectIds],
    );
    return rows.map((r) => ({
      id: r.id,
      subjectType: r.subject_type,
      subjectId: r.subject_id,
      reason: r.reason,
      active: r.active,
      createdAt: r.created_at,
      releasedAt: r.released_at,
    }));
  }

  /**
   * Compute which candidates may be purged, excluding records under an active
   * legal hold, subject to mandatory retention, or still within their window.
   */
  async calculateEligibility(
    candidates: PurgeCandidate[],
    now: Date = new Date(),
  ): Promise<PurgeEligibility> {
    const eligible: PurgeCandidate[] = [];
    const excluded: PurgeEligibility['excluded'] = [];

    const byType = new Map<string, string[]>();
    for (const c of candidates) {
      const list = byType.get(c.subjectType) ?? [];
      list.push(c.subjectId);
      byType.set(c.subjectType, list);
    }

    const heldKeys = new Set<string>();
    for (const [subjectType, ids] of byType) {
      const holds = await this.getActiveHolds(subjectType, ids);
      for (const hold of holds) {
        heldKeys.add(`${hold.subjectType}:${hold.subjectId}`);
      }
    }

    const policyCache = new Map<RetentionCategory, RetentionPolicy>();
    for (const candidate of candidates) {
      if (heldKeys.has(`${candidate.subjectType}:${candidate.subjectId}`)) {
        excluded.push({ candidate, reason: 'legal_hold' });
        continue;
      }

      let policy = policyCache.get(candidate.retentionCategory);
      if (!policy) {
        policy = await this.getPolicy(candidate.retentionCategory);
        policyCache.set(candidate.retentionCategory, policy);
      }

      if (policy.mandatory) {
        excluded.push({ candidate, reason: 'mandatory_retention' });
        continue;
      }

      const ageMs = now.getTime() - candidate.createdAt.getTime();
      const ageDays = ageMs / (1000 * 60 * 60 * 24);
      if (ageDays < policy.retentionDays) {
        excluded.push({ candidate, reason: 'within_retention_window' });
        continue;
      }

      eligible.push(candidate);
    }

    return { eligible, excluded };
  }
}

export interface PurgeOptions {
  subjectType: string;
  legalBasis: string;
  batchSize?: number;
}

export class PurgeService {
  private readonly retention: RetentionPolicyService;

  constructor(private readonly pool: Pool) {
    this.retention = new RetentionPolicyService(pool);
  }

  /**
   * Run a purge batch: compute eligibility, delete only eligible records, and
   * persist the legal basis and outcome for the batch.
   */
  async purge(options: PurgeOptions): Promise<PurgeBatchOutcome> {
    const { subjectType, legalBasis, batchSize = 500 } = options;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const candidates = await this.loadCandidates(client, subjectType, batchSize);
      const { eligible, excluded } = await this.retention.calculateEligibility(candidates);

      const excludedReasons: Record<string, number> = {};
      for (const e of excluded) {
        excludedReasons[e.reason] = (excludedReasons[e.reason] ?? 0) + 1;
      }

      let deletedCount = 0;
      if (eligible.length > 0) {
        const ids = eligible.map((c) => c.id);
        const result = await client.query(
          'DELETE FROM purgeable_records WHERE id = ANY($1::uuid[])',
          [ids],
        );
        deletedCount = result.rowCount ?? 0;
      }

      const batch = await client.query<{ id: string }>(
        `INSERT INTO purge_batches
           (subject_type, legal_basis, eligible_count, excluded_count, deleted_count, excluded_reasons, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())
         RETURNING id`,
        [
          subjectType,
          legalBasis,
          eligible.length,
          excluded.length,
          deletedCount,
          JSON.stringify(excludedReasons),
        ],
      );
      const batchId = batch.rows[0].id;

      await client.query('COMMIT');

      logger.info('purge batch completed', {
        batchId,
        subjectType,
        legalBasis,
        eligibleCount: eligible.length,
        excludedCount: excluded.length,
        deletedCount,
      });

      return {
        batchId,
        legalBasis,
        eligibleCount: eligible.length,
        excludedCount: excluded.length,
        deletedCount,
        excludedReasons,
      };
    } catch (err) {
      await client.query('ROLLBACK');
      logger.error('purge batch failed', { subjectType, legalBasis, error: err });
      throw err;
    } finally {
      client.release();
    }
  }

  private async loadCandidates(
    client: PoolClient,
    subjectType: string,
    batchSize: number,
  ): Promise<PurgeCandidate[]> {
    const { rows } = await client.query<{
      id: string;
      subject_type: string;
      subject_id: string;
      created_at: Date;
      retention_category: RetentionCategory;
    }>(
      `SELECT id, subject_type, subject_id, created_at, retention_category
         FROM purgeable_records
        WHERE subject_type = $1
        ORDER BY created_at ASC
        LIMIT $2
        FOR UPDATE SKIP LOCKED`,
      [subjectType, batchSize],
    );
    return rows.map((r) => ({
      id: r.id,
      subjectType: r.subject_type,
      subjectId: r.subject_id,
      createdAt: r.created_at,
      retentionCategory: r.retention_category,
    }));
  }
}
