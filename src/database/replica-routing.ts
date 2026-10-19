import { Logger } from '@nestjs/common';

/**
 * Stale-replica fallback policy.
 *
 * Read replicas are used for non-critical reads. When replication lag exceeds
 * the configured threshold, critical reads (payment / account state) are routed
 * to the primary database so clients never observe stale financial state.
 */

export type ReadKind = 'critical' | 'non-critical';

export type ReplicaTarget = 'primary' | 'replica';

export interface ReplicaRoutingOptions {
  /** Max acceptable replication lag (ms) before critical reads fall back. */
  lagThresholdMs: number;
  /** Returns the current replication lag in ms, or null if unknown. */
  getReplicationLagMs: () => number | null;
  logger?: Pick<Logger, 'warn' | 'debug'>;
}

export interface FallbackCounters {
  /** Critical reads routed to primary because lag exceeded the threshold. */
  criticalFallbacks: number;
  /** Critical reads routed to primary because lag was unknown. */
  unknownLagFallbacks: number;
  /** Total routing decisions evaluated. */
  totalDecisions: number;
}

export class ReplicaRouter {
  private readonly counters: FallbackCounters = {
    criticalFallbacks: 0,
    unknownLagFallbacks: 0,
    totalDecisions: 0,
  };

  constructor(private readonly options: ReplicaRoutingOptions) {}

  /**
   * Decide which database target should serve a read.
   *
   * - Non-critical reads always go to the replica.
   * - Critical reads go to the replica only when lag is known and within the
   *   threshold; otherwise they fall back to the primary.
   */
  route(kind: ReadKind): ReplicaTarget {
    this.counters.totalDecisions += 1;

    if (kind === 'non-critical') {
      return 'replica';
    }

    const lagMs = this.options.getReplicationLagMs();

    if (lagMs === null || lagMs === undefined) {
      this.counters.unknownLagFallbacks += 1;
      this.options.logger?.warn(
        'Replication lag unknown; routing critical read to primary',
      );
      return 'primary';
    }

    if (lagMs > this.options.lagThresholdMs) {
      this.counters.criticalFallbacks += 1;
      this.options.logger?.warn(
        `Replication lag ${lagMs}ms exceeds threshold ${this.options.lagThresholdMs}ms; routing critical read to primary`,
      );
      return 'primary';
    }

    this.options.logger?.debug(
      `Replication lag ${lagMs}ms within threshold; routing critical read to replica`,
    );
    return 'replica';
  }

  /** Snapshot of fallback counters for metrics export. */
  getCounters(): Readonly<FallbackCounters> {
    return { ...this.counters };
  }

  /** Reset counters (useful in tests). */
  resetCounters(): void {
    this.counters.criticalFallbacks = 0;
    this.counters.unknownLagFallbacks = 0;
    this.counters.totalDecisions = 0;
  }
}
