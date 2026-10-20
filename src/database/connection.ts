import { Pool, PoolClient, QueryResult, QueryResultRow } from 'pg';
import { databaseConfig } from '../config/database.config';
import { logger } from '../utils/logger';

/**
 * Replication-lag threshold (in seconds) above which critical reads are
 * routed to the primary database instead of a read replica.
 */
const REPLICA_LAG_THRESHOLD_SECONDS = Number(
  process.env.REPLICA_LAG_THRESHOLD_SECONDS ?? 5,
);

/**
 * Counters tracking how often critical reads fall back to the primary
 * because the replica lag exceeded the configured threshold.
 */
export const replicaFallbackMetrics = {
  criticalReadFallbacks: 0,
  replicaLagChecks: 0,
  lastObservedLagSeconds: 0,
};

/**
 * Reads are considered critical when they touch payment or account state.
 * These must never be served from a stale replica.
 */
const CRITICAL_READ_PATTERN = /\b(payments?|accounts?|balances?|transactions?|ledger)\b/i;

export function isCriticalRead(sql: string): boolean {
  return CRITICAL_READ_PATTERN.test(sql);
}

/**
 * Measures current replication lag on the primary in seconds.
 * Returns Infinity when lag cannot be determined so callers fail safe
 * by routing to the primary.
 */
async function getReplicationLagSeconds(primary: Pool): Promise<number> {
  try {
    const result = await primary.query<{ lag_seconds: string | null }>(
      `SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())) AS lag_seconds`,
    );
    const raw = result.rows[0]?.lag_seconds;
    if (raw === null || raw === undefined) {
      return 0;
    }
    const lag = Number(raw);
    return Number.isFinite(lag) ? lag : Infinity;
  } catch (error) {
    logger.warn('Unable to determine replication lag; defaulting to primary', {
      error: (error as Error).message,
    });
    return Infinity;
  }
}

/**
 * Decides whether a read should be served from the primary because the
 * replica is too far behind. Non-critical reads keep using the replica.
 */
async function shouldFallbackToPrimary(sql: string): Promise<boolean> {
  if (!isCriticalRead(sql)) {
    return false;
  }

  replicaFallbackMetrics.replicaLagChecks += 1;
  const lag = await getReplicationLagSeconds(primaryPool);
  replicaFallbackMetrics.lastObservedLagSeconds = lag;

  if (lag > REPLICA_LAG_THRESHOLD_SECONDS) {
    replicaFallbackMetrics.criticalReadFallbacks += 1;
    logger.warn('Replica lag exceeds threshold; routing critical read to primary', {
      lagSeconds: lag,
      thresholdSeconds: REPLICA_LAG_THRESHOLD_SECONDS,
    });
    return true;
  }

  return false;
}

const primaryPool = new Pool({
  ...databaseConfig,
  connectionString: databaseConfig.primaryUrl ?? databaseConfig.url,
});

const replicaPool = databaseConfig.replicaUrl
  ? new Pool({
      ...databaseConfig,
      connectionString: databaseConfig.replicaUrl,
    })
  : null;

primaryPool.on('error', (error) => {
  logger.error('Unexpected error on primary database pool', {
    error: error.message,
  });
});

replicaPool?.on('error', (error) => {
  logger.error('Unexpected error on replica database pool', {
    error: error.message,
  });
});

/**
 * Executes a query, routing critical reads to the primary when the replica
 * lag exceeds the configured threshold.
 */
export async function query<T extends QueryResultRow = QueryResultRow>(
  sql: string,
  params?: unknown[],
): Promise<QueryResult<T>> {
  const usePrimary = await shouldFallbackToPrimary(sql);
  const pool = usePrimary || !replicaPool ? primaryPool : replicaPool;
  return pool.query<T>(sql, params as never);
}

/**
 * Acquires a client from the primary pool. Writes and transactions must
 * always use the primary.
 */
export async function getClient(): Promise<PoolClient> {
  return primaryPool.connect();
}

export async function closePools(): Promise<void> {
  await primaryPool.end();
  await replicaPool?.end();
}

export { primaryPool, replicaPool, REPLICA_LAG_THRESHOLD_SECONDS };
