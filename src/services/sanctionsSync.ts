import { EventEmitter } from 'events';
import { Pool } from 'pg';
import { Counter, Gauge } from 'prom-client';
import { logger } from '../utils/logger';

export interface SanctionsListSource {
  id: string;
  name: string;
  url: string;
  version: string;
  lastSyncedAt: Date;
  entryCount: number;
}

export interface SanctionsSyncPolicy {
  /** Maximum allowed age (ms) of a synced list before it is considered stale. */
  maxSyncAgeMs: number;
  /** When true, screening is blocked if the list is stale. */
  blockScreeningWhenStale: boolean;
}

export interface ScreeningSnapshot {
  listSourceId: string;
  listVersion: string;
  listLastSyncedAt: Date;
  listAgeMs: number;
  stale: boolean;
  outcome: 'clear' | 'match' | 'blocked_stale';
  screenedAt: Date;
}

export const DEFAULT_SANCTIONS_SYNC_POLICY: SanctionsSyncPolicy = {
  maxSyncAgeMs: 24 * 60 * 60 * 1000,
  blockScreeningWhenStale: true,
};

const sanctionsSyncAgeGauge = new Gauge({
  name: 'sanctions_list_sync_age_seconds',
  help: 'Age in seconds since the sanctions list was last synced',
  labelNames: ['source_id', 'source_name'],
});

const sanctionsSyncStaleGauge = new Gauge({
  name: 'sanctions_list_stale',
  help: 'Whether the sanctions list is stale (1) or fresh (0)',
  labelNames: ['source_id', 'source_name'],
});

const sanctionsSyncStaleAlertCounter = new Counter({
  name: 'sanctions_list_stale_alerts_total',
  help: 'Number of stale sanctions list alerts emitted',
  labelNames: ['source_id', 'source_name'],
});

export class SanctionsSyncService extends EventEmitter {
  private readonly pool: Pool;
  private readonly policy: SanctionsSyncPolicy;

  constructor(pool: Pool, policy: SanctionsSyncPolicy = DEFAULT_SANCTIONS_SYNC_POLICY) {
    super();
    this.pool = pool;
    this.policy = policy;
  }

  /**
   * Persist the synced list source/version metadata. Called by the sync job after
   * a successful download so freshness is auditable.
   */
  async recordSync(source: {
    id: string;
    name: string;
    url: string;
    version: string;
    entryCount: number;
  }): Promise<SanctionsListSource> {
    const lastSyncedAt = new Date();
    const result = await this.pool.query(
      `INSERT INTO sanctions_list_sources (id, name, url, version, last_synced_at, entry_count)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         url = EXCLUDED.url,
         version = EXCLUDED.version,
         last_synced_at = EXCLUDED.last_synced_at,
         entry_count = EXCLUDED.entry_count
       RETURNING id, name, url, version, last_synced_at, entry_count`,
      [source.id, source.name, source.url, source.version, lastSyncedAt, source.entryCount],
    );
    const row = result.rows[0];
    const listSource: SanctionsListSource = {
      id: row.id,
      name: row.name,
      url: row.url,
      version: row.version,
      lastSyncedAt: row.last_synced_at,
      entryCount: row.entry_count,
    };
    this.updateMetrics(listSource);
    return listSource;
  }

  async getListSource(id: string): Promise<SanctionsListSource | null> {
    const result = await this.pool.query(
      `SELECT id, name, url, version, last_synced_at, entry_count
       FROM sanctions_list_sources WHERE id = $1`,
      [id],
    );
    if (result.rows.length === 0) {
      return null;
    }
    const row = result.rows[0];
    return {
      id: row.id,
      name: row.name,
      url: row.url,
      version: row.version,
      lastSyncedAt: row.last_synced_at,
      entryCount: row.entry_count,
    };
  }

  isStale(listSource: SanctionsListSource, now: Date = new Date()): boolean {
    return now.getTime() - listSource.lastSyncedAt.getTime() > this.policy.maxSyncAgeMs;
  }

  /**
   * Build a screening snapshot capturing the list version/freshness that produced
   * the outcome, so each screening result is auditable and replayable.
   */
  buildScreeningSnapshot(
    listSource: SanctionsListSource,
    matched: boolean,
    now: Date = new Date(),
  ): ScreeningSnapshot {
    const listAgeMs = now.getTime() - listSource.lastSyncedAt.getTime();
    const stale = listAgeMs > this.policy.maxSyncAgeMs;
    let outcome: ScreeningSnapshot['outcome'];
    if (stale && this.policy.blockScreeningWhenStale) {
      outcome = 'blocked_stale';
    } else if (matched) {
      outcome = 'match';
    } else {
      outcome = 'clear';
    }
    return {
      listSourceId: listSource.id,
      listVersion: listSource.version,
      listLastSyncedAt: listSource.lastSyncedAt,
      listAgeMs,
      stale,
      outcome,
      screenedAt: now,
    };
  }

  /**
   * Persist a screening snapshot alongside the screening result.
   */
  async persistScreeningSnapshot(screeningId: string, snapshot: ScreeningSnapshot): Promise<void> {
    await this.pool.query(
      `INSERT INTO sanctions_screening_snapshots
         (screening_id, list_source_id, list_version, list_last_synced_at, list_age_ms, stale, outcome, screened_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        screeningId,
        snapshot.listSourceId,
        snapshot.listVersion,
        snapshot.listLastSyncedAt,
        snapshot.listAgeMs,
        snapshot.stale,
        snapshot.outcome,
        snapshot.screenedAt,
      ],
    );
  }

  /**
   * Check freshness of all known list sources and emit alerts when sync age
   * exceeds the configured policy threshold.
   */
  async checkFreshnessAndAlert(now: Date = new Date()): Promise<SanctionsListSource[]> {
    const result = await this.pool.query(
      `SELECT id, name, url, version, last_synced_at, entry_count FROM sanctions_list_sources`,
    );
    const staleSources: SanctionsListSource[] = [];
    for (const row of result.rows) {
      const listSource: SanctionsListSource = {
        id: row.id,
        name: row.name,
        url: row.url,
        version: row.version,
        lastSyncedAt: row.last_synced_at,
        entryCount: row.entry_count,
      };
      this.updateMetrics(listSource, now);
      if (this.isStale(listSource, now)) {
        staleSources.push(listSource);
        sanctionsSyncStaleAlertCounter.inc({ source_id: listSource.id, source_name: listSource.name });
        logger.warn('Sanctions list sync age exceeds policy threshold', {
          sourceId: listSource.id,
          sourceName: listSource.name,
          version: listSource.version,
          lastSyncedAt: listSource.lastSyncedAt.toISOString(),
          maxSyncAgeMs: this.policy.maxSyncAgeMs,
        });
        this.emit('stale', listSource);
      }
    }
    return staleSources;
  }

  private updateMetrics(listSource: SanctionsListSource, now: Date = new Date()): void {
    const ageSeconds = Math.max(0, (now.getTime() - listSource.lastSyncedAt.getTime()) / 1000);
    const labels = { source_id: listSource.id, source_name: listSource.name };
    sanctionsSyncAgeGauge.set(labels, ageSeconds);
    sanctionsSyncStaleGauge.set(labels, this.isStale(listSource, now) ? 1 : 0);
  }
}
