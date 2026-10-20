import { env } from './env';

/**
 * Database connection budget.
 *
 * PostgreSQL deployments have a hard `max_connections` limit (often 100 on
 * managed instances). Every app instance opens its own primary + write pools,
 * and read replicas multiply the effective fan-out. The defaults below are
 * deliberately conservative so a small number of instances cannot exhaust the
 * server's connection slots.
 *
 * PgBouncer interaction:
 * - With `transaction` pooling, server-side connections are multiplexed per
 *   transaction, so the pool sizes here bound *client* connections to PgBouncer
 *   rather than PostgreSQL itself. Keep them modest anyway; PgBouncer's own
 *   `default_pool_size` / `max_db_connections` still cap the backend.
 * - With `session` pooling (or no PgBouncer), every pooled client holds a real
 *   PostgreSQL backend for its lifetime, so the aggregate budget below is the
 *   actual server-side connection count. Size it against `max_connections`
 *   minus reserved superuser slots.
 */

const DEFAULT_PRIMARY_POOL_MAX = 10;
const DEFAULT_WRITE_POOL_MAX = 5;
const DEFAULT_APP_INSTANCES = 1;
const DEFAULT_REPLICA_COUNT = 0;

function readInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

export interface PoolBudget {
  primaryMax: number;
  writeMax: number;
  appInstances: number;
  replicaCount: number;
  /** Total connections this deployment may open against PostgreSQL. */
  aggregate: number;
  /** Server-side connection ceiling the deployment must stay under. */
  budget: number;
}

export function resolvePoolBudget(): PoolBudget {
  const primaryMax = readInt('DB_POOL_PRIMARY_MAX', DEFAULT_PRIMARY_POOL_MAX);
  const writeMax = readInt('DB_POOL_WRITE_MAX', DEFAULT_WRITE_POOL_MAX);
  const appInstances = Math.max(
    1,
    readInt('DB_APP_INSTANCES', DEFAULT_APP_INSTANCES),
  );
  const replicaCount = readInt('DB_REPLICA_COUNT', DEFAULT_REPLICA_COUNT);
  const budget = readInt('DB_CONNECTION_BUDGET', 100);

  // Each instance opens a primary pool and a write pool; replicas add read
  // pools sized like the primary pool.
  const perInstance = primaryMax + writeMax + replicaCount * primaryMax;
  const aggregate = perInstance * appInstances;

  return { primaryMax, writeMax, appInstances, replicaCount, aggregate, budget };
}

/**
 * Validate aggregate pool sizing at startup. Fails fast when the deployment
 * would exceed the connection budget; warns when it consumes most of it.
 */
export function validatePoolBudget(budget: PoolBudget = resolvePoolBudget()): PoolBudget {
  if (budget.aggregate > budget.budget) {
    throw new Error(
      `Database pool budget exceeded: ${budget.aggregate} connections requested ` +
        `(${budget.appInstances} instance(s) x [primary ${budget.primaryMax} + write ` +
        `${budget.writeMax} + ${budget.replicaCount} replica(s) x ${budget.primaryMax}]) ` +
        `but DB_CONNECTION_BUDGET is ${budget.budget}. Lower DB_POOL_PRIMARY_MAX / ` +
        `DB_POOL_WRITE_MAX or raise DB_CONNECTION_BUDGET.`,
    );
  }

  if (budget.aggregate > budget.budget * 0.8) {
    // eslint-disable-next-line no-console
    console.warn(
      `[db] Pool sizing uses ${budget.aggregate}/${budget.budget} connections ` +
        `(${Math.round((budget.aggregate / budget.budget) * 100)}% of budget). ` +
        `Leave headroom for migrations and admin sessions.`,
    );
  }

  return budget;
}

const poolBudget = validatePoolBudget();

export const databaseConfig = {
  primary: {
    max: poolBudget.primaryMax,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  },
  write: {
    max: poolBudget.writeMax,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  },
  replica: {
    max: poolBudget.primaryMax,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  },
  budget: poolBudget,
};

export default databaseConfig;
