/**
 * Database metrics registry.
 *
 * Tracks connection-pool and replica-routing signals. The stale-replica
 * fallback counters below record how often critical reads (payment/account
 * state) are routed to the primary because replica lag exceeded the
 * configured threshold.
 */

export interface DatabaseMetricsSnapshot {
  poolSize: number;
  activeConnections: number;
  idleConnections: number;
  waitingClients: number;
  replicaFallbackTotal: number;
  replicaFallbackByReason: Record<string, number>;
  lastReplicaLagMs: number | null;
}

export type ReplicaFallbackReason =
  | 'lag_exceeded'
  | 'replica_unavailable'
  | 'no_replica';

class DatabaseMetrics {
  private poolSize = 0;
  private activeConnections = 0;
  private idleConnections = 0;
  private waitingClients = 0;
  private replicaFallbackTotal = 0;
  private replicaFallbackByReason: Record<string, number> = {};
  private lastReplicaLagMs: number | null = null;

  setPoolStats(stats: {
    poolSize?: number;
    activeConnections?: number;
    idleConnections?: number;
    waitingClients?: number;
  }): void {
    if (stats.poolSize !== undefined) this.poolSize = stats.poolSize;
    if (stats.activeConnections !== undefined) {
      this.activeConnections = stats.activeConnections;
    }
    if (stats.idleConnections !== undefined) {
      this.idleConnections = stats.idleConnections;
    }
    if (stats.waitingClients !== undefined) {
      this.waitingClients = stats.waitingClients;
    }
  }

  /**
   * Record the most recently observed replication lag (in milliseconds).
   */
  recordReplicaLag(lagMs: number | null): void {
    this.lastReplicaLagMs = lagMs;
  }

  /**
   * Increment the stale-replica fallback counter. Called whenever a critical
   * read is routed to the primary instead of a lagging replica.
   */
  recordReplicaFallback(reason: ReplicaFallbackReason = 'lag_exceeded'): void {
    this.replicaFallbackTotal += 1;
    this.replicaFallbackByReason[reason] =
      (this.replicaFallbackByReason[reason] ?? 0) + 1;
  }

  getReplicaFallbackTotal(): number {
    return this.replicaFallbackTotal;
  }

  snapshot(): DatabaseMetricsSnapshot {
    return {
      poolSize: this.poolSize,
      activeConnections: this.activeConnections,
      idleConnections: this.idleConnections,
      waitingClients: this.waitingClients,
      replicaFallbackTotal: this.replicaFallbackTotal,
      replicaFallbackByReason: { ...this.replicaFallbackByReason },
      lastReplicaLagMs: this.lastReplicaLagMs,
    };
  }

  reset(): void {
    this.poolSize = 0;
    this.activeConnections = 0;
    this.idleConnections = 0;
    this.waitingClients = 0;
    this.replicaFallbackTotal = 0;
    this.replicaFallbackByReason = {};
    this.lastReplicaLagMs = null;
  }
}

export const databaseMetrics = new DatabaseMetrics();
export { DatabaseMetrics };
