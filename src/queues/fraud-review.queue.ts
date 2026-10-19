import { Queue, Worker, Job, JobsOptions } from 'bullmq';
import { Pool } from 'pg';
import { redis } from '../config/redis';

export type FraudReviewStatus =
  | 'pending'
  | 'assigned'
  | 'in_review'
  | 'escalated'
  | 'resolved'
  | 'dismissed';

export interface FraudReviewCase {
  id: string;
  subjectId: string;
  reason: string;
  riskScore: number;
  status: FraudReviewStatus;
  ownerId: string | null;
  escalated: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface FraudReviewDecision {
  id: string;
  caseId: string;
  actorId: string;
  action: 'assign' | 'status' | 'escalate' | 'deescalate' | 'decision';
  fromStatus: FraudReviewStatus | null;
  toStatus: FraudReviewStatus | null;
  note: string | null;
  createdAt: string;
}

const QUEUE_NAME = 'fraud-review';

let pool: Pool | null = null;
function getPool(): Pool {
  if (!pool) {
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
  }
  return pool;
}

let reviewQueue: Queue<{ caseId: string }> | null = null;
export function getFraudReviewQueue(): Queue<{ caseId: string }> {
  if (!reviewQueue) {
    reviewQueue = new Queue<{ caseId: string }>(QUEUE_NAME, {
      connection: redis,
      defaultJobOptions: {
        attempts: 5,
        backoff: { type: 'exponential', delay: 5000 },
        removeOnComplete: 1000,
        removeOnFail: 5000,
      },
    });
  }
  return reviewQueue;
}

async function recordDecision(
  client: Pool | PoolClientLike,
  decision: Omit<FraudReviewDecision, 'id' | 'createdAt'>,
): Promise<void> {
  await client.query(
    `INSERT INTO fraud_review_decisions
       (case_id, actor_id, action, from_status, to_status, note)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      decision.caseId,
      decision.actorId,
      decision.action,
      decision.fromStatus,
      decision.toStatus,
      decision.note,
    ],
  );
}

interface PoolClientLike {
  query: (text: string, values?: unknown[]) => Promise<unknown>;
}

export async function enqueueFraudReview(input: {
  subjectId: string;
  reason: string;
  riskScore: number;
}): Promise<FraudReviewCase> {
  const db = getPool();
  const { rows } = await db.query<FraudReviewCase>(
    `INSERT INTO fraud_review_cases (subject_id, reason, risk_score, status)
     VALUES ($1, $2, $3, 'pending')
     RETURNING id, subject_id AS "subjectId", reason,
               risk_score AS "riskScore", status, owner_id AS "ownerId",
               escalated, created_at AS "createdAt", updated_at AS "updatedAt"`,
    [input.subjectId, input.reason, input.riskScore],
  );
  const reviewCase = rows[0];
  await recordDecision(db, {
    caseId: reviewCase.id,
    actorId: 'system',
    action: 'status',
    fromStatus: null,
    toStatus: 'pending',
    note: 'case created',
  });
  await getFraudReviewQueue().add(
    'review',
    { caseId: reviewCase.id },
    { jobId: reviewCase.id } as JobsOptions,
  );
  return reviewCase;
}

export async function getFraudReviewCase(id: string): Promise<FraudReviewCase | null> {
  const { rows } = await getPool().query<FraudReviewCase>(
    `SELECT id, subject_id AS "subjectId", reason, risk_score AS "riskScore",
            status, owner_id AS "ownerId", escalated,
            created_at AS "createdAt", updated_at AS "updatedAt"
       FROM fraud_review_cases WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
}

export async function listFraudReviewCases(filter: {
  status?: FraudReviewStatus;
  ownerId?: string;
  escalated?: boolean;
  limit?: number;
  offset?: number;
}): Promise<FraudReviewCase[]> {
  const clauses: string[] = [];
  const values: unknown[] = [];
  if (filter.status) {
    values.push(filter.status);
    clauses.push(`status = $${values.length}`);
  }
  if (filter.ownerId) {
    values.push(filter.ownerId);
    clauses.push(`owner_id = $${values.length}`);
  }
  if (typeof filter.escalated === 'boolean') {
    values.push(filter.escalated);
    clauses.push(`escalated = $${values.length}`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  values.push(filter.limit ?? 50, filter.offset ?? 0);
  const { rows } = await getPool().query<FraudReviewCase>(
    `SELECT id, subject_id AS "subjectId", reason, risk_score AS "riskScore",
            status, owner_id AS "ownerId", escalated,
            created_at AS "createdAt", updated_at AS "updatedAt"
       FROM fraud_review_cases ${where}
      ORDER BY created_at ASC
      LIMIT $${values.length - 1} OFFSET $${values.length}`,
    values,
  );
  return rows;
}

export async function getFraudReviewHistory(caseId: string): Promise<FraudReviewDecision[]> {
  const { rows } = await getPool().query<FraudReviewDecision>(
    `SELECT id, case_id AS "caseId", actor_id AS "actorId", action,
            from_status AS "fromStatus", to_status AS "toStatus", note,
            created_at AS "createdAt"
       FROM fraud_review_decisions
      WHERE case_id = $1
      ORDER BY created_at ASC`,
    [caseId],
  );
  return rows;
}

export async function assignFraudReviewCase(
  caseId: string,
  ownerId: string,
  actorId: string,
): Promise<FraudReviewCase | null> {
  const db = getPool();
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query<FraudReviewCase>(
      `UPDATE fraud_review_cases
          SET owner_id = $2, status = CASE WHEN status = 'pending' THEN 'assigned' ELSE status END,
              updated_at = now()
        WHERE id = $1
        RETURNING id, subject_id AS "subjectId", reason, risk_score AS "riskScore",
                  status, owner_id AS "ownerId", escalated,
                  created_at AS "createdAt", updated_at AS "updatedAt"`,
      [caseId, ownerId],
    );
    if (!rows[0]) {
      await client.query('ROLLBACK');
      return null;
    }
    await recordDecision(client, {
      caseId,
      actorId,
      action: 'assign',
      fromStatus: null,
      toStatus: rows[0].status,
      note: `owner=${ownerId}`,
    });
    await client.query('COMMIT');
    return rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function transitionFraudReviewStatus(
  caseId: string,
  toStatus: FraudReviewStatus,
  actorId: string,
  note?: string,
): Promise<FraudReviewCase | null> {
  const db = getPool();
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query<{ status: FraudReviewStatus }>(
      `SELECT status FROM fraud_review_cases WHERE id = $1 FOR UPDATE`,
      [caseId],
    );
    if (!current.rows[0]) {
      await client.query('ROLLBACK');
      return null;
    }
    const fromStatus = current.rows[0].status;
    const { rows } = await client.query<FraudReviewCase>(
      `UPDATE fraud_review_cases
          SET status = $2, updated_at = now()
        WHERE id = $1
        RETURNING id, subject_id AS "subjectId", reason, risk_score AS "riskScore",
                  status, owner_id AS "ownerId", escalated,
                  created_at AS "createdAt", updated_at AS "updatedAt"`,
      [caseId, toStatus],
    );
    await recordDecision(client, {
      caseId,
      actorId,
      action: 'status',
      fromStatus,
      toStatus,
      note: note ?? null,
    });
    await client.query('COMMIT');
    return rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function setFraudReviewEscalation(
  caseId: string,
  escalated: boolean,
  actorId: string,
  note?: string,
): Promise<FraudReviewCase | null> {
  const db = getPool();
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query<FraudReviewCase>(
      `UPDATE fraud_review_cases
          SET escalated = $2,
              status = CASE WHEN $2 THEN 'escalated' ELSE status END,
              updated_at = now()
        WHERE id = $1
        RETURNING id, subject_id AS "subjectId", reason, risk_score AS "riskScore",
                  status, owner_id AS "ownerId", escalated,
                  created_at AS "createdAt", updated_at AS "updatedAt"`,
      [caseId, escalated],
    );
    if (!rows[0]) {
      await client.query('ROLLBACK');
      return null;
    }
    await recordDecision(client, {
      caseId,
      actorId,
      action: escalated ? 'escalate' : 'deescalate',
      fromStatus: null,
      toStatus: rows[0].status,
      note: note ?? null,
    });
    await client.query('COMMIT');
    return rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export function startFraudReviewWorker(
  handler: (job: Job<{ caseId: string }>) => Promise<void>,
): Worker<{ caseId: string }> {
  return new Worker<{ caseId: string }>(QUEUE_NAME, handler, {
    connection: redis,
    concurrency: 5,
  });
}
