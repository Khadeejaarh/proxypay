import { Module, Global, DynamicModule, Logger } from '@nestjs/common';
import { Pool } from 'pg';

export const PG_POOL = 'PG_POOL';
export const PG_WRITE_POOL = 'PG_WRITE_POOL';
export const PG_REPLICA_POOL = 'PG_REPLICA_POOL';

/**
 * Conservative default connection budget.
 *
 * PostgreSQL's default max_connections is 100. With replicas and multiple
 * app instances sharing that budget, a per-pool default of 1,000 is unsafe.
 * We default each pool to a small size and validate the aggregate at startup.
 */
export const DEFAULT_POOL_MAX = 10;
export const DEFAULT_REPLICA_POOL_MAX = 10;

/**
 * Total connections this process may open across all pools.
 * Override via DB_CONNECTION_BUDGET when the deployment provisions more.
 */
export const DEFAULT_CONNECTION_BUDGET = 40;

export interface PoolConfig {
  connectionString?: string;
  max: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
}

export interface DatabaseModuleOptions {
  primaryUrl?: string;
  writeUrl?: string;
  replicaUrls?: string[];
  /** Max connections per pool. Defaults to DEFAULT_POOL_MAX. */
  poolMax?: number;
  /** Max connections per replica pool. Defaults to DEFAULT_REPLICA_POOL_MAX. */
  replicaPoolMax?: number;
  /** Total connections allowed for this process. Defaults to DEFAULT_CONNECTION_BUDGET. */
  connectionBudget?: number;
  /** Number of app instances sharing the database. Defaults to 1. */
  appInstances?: number;
}

function readInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function buildPoolConfig(connectionString: string | undefined, max: number): PoolConfig {
  return {
    connectionString,
    max,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  };
}

/**
 * Validate aggregate pool sizing against the connection budget.
 *
 * Aggregate = (primary + write + replicas) * appInstances.
 * Fails fast when the budget is exceeded so misconfiguration surfaces at
 * startup rather than as PostgreSQL "too many clients" errors under load.
 */
export function validateConnectionBudget(options: DatabaseModuleOptions): void {
  const logger = new Logger('DatabaseModule');
  const poolMax = options.poolMax ?? DEFAULT_POOL_MAX;
  const replicaPoolMax = options.replicaPoolMax ?? DEFAULT_REPLICA_POOL_MAX;
  const budget = options.connectionBudget ?? DEFAULT_CONNECTION_BUDGET;
  const appInstances = options.appInstances ?? 1;
  const replicaCount = options.replicaUrls?.length ?? 0;

  const perInstance = poolMax * 2 + replicaPoolMax * replicaCount;
  const aggregate = perInstance * appInstances;

  if (aggregate > budget) {
    throw new Error(
      `Database connection budget exceeded: ${aggregate} connections requested ` +
        `(${perInstance} per instance x ${appInstances} instances) but budget is ${budget}. ` +
        `Reduce pool sizes or raise DB_CONNECTION_BUDGET.`,
    );
  }

  if (aggregate > budget * 0.8) {
    logger.warn(
      `Database connection usage is near budget: ${aggregate}/${budget} connections. ` +
        `Consider PgBouncer in transaction pooling mode to multiplex connections.`,
    );
  }
}

@Global()
@Module({})
export class DatabaseModule {
  static forRoot(options: DatabaseModuleOptions = {}): DynamicModule {
    validateConnectionBudget(options);

    const poolMax = options.poolMax ?? DEFAULT_POOL_MAX;
    const replicaPoolMax = options.replicaPoolMax ?? DEFAULT_REPLICA_POOL_MAX;

    const primaryProvider = {
      provide: PG_POOL,
      useFactory: () => new Pool(buildPoolConfig(options.primaryUrl, poolMax)),
    };

    const writeProvider = {
      provide: PG_WRITE_POOL,
      useFactory: () => new Pool(buildPoolConfig(options.writeUrl ?? options.primaryUrl, poolMax)),
    };

    const replicaProviders = (options.replicaUrls ?? []).map((url, index) => ({
      provide: `${PG_REPLICA_POOL}_${index}`,
      useFactory: () => new Pool(buildPoolConfig(url, replicaPoolMax)),
    }));

    return {
      module: DatabaseModule,
      providers: [primaryProvider, writeProvider, ...replicaProviders],
      exports: [PG_POOL, PG_WRITE_POOL, ...replicaProviders.map((p) => p.provide)],
    };
  }
}
