import { EventEmitter } from 'events';

export interface SanctionsListVersion {
  source: string;
  version: string;
  syncedAt: Date;
}

export interface SanctionsScreeningSnapshot {
  listSource: string;
  listVersion: string;
  listSyncedAt: Date;
  syncAgeMs: number;
  stale: boolean;
  outcome: 'clear' | 'match' | 'stale_list';
  screenedAt: Date;
}

export interface SanctionsScreeningResult {
  matched: boolean;
  snapshot: SanctionsScreeningSnapshot;
}

export interface SanctionsScreeningPolicy {
  maxSyncAgeMs: number;
  onStaleList: 'block' | 'allow';
}

export interface SanctionsSyncAlert {
  type: 'sanctions_sync_stale';
  source: string;
  version: string;
  syncedAt: Date;
  syncAgeMs: number;
  maxSyncAgeMs: number;
  severity: 'warning' | 'critical';
}

export const DEFAULT_SANCTIONS_POLICY: SanctionsScreeningPolicy = {
  maxSyncAgeMs: 24 * 60 * 60 * 1000,
  onStaleList: 'block',
};

export class SanctionsScreeningService {
  private listVersion: SanctionsListVersion | null = null;
  private readonly alerts = new EventEmitter();

  constructor(private readonly policy: SanctionsScreeningPolicy = DEFAULT_SANCTIONS_POLICY) {}

  recordListSync(source: string, version: string, syncedAt: Date = new Date()): SanctionsListVersion {
    this.listVersion = { source, version, syncedAt };
    return this.listVersion;
  }

  getListVersion(): SanctionsListVersion | null {
    return this.listVersion;
  }

  onAlert(listener: (alert: SanctionsSyncAlert) => void): void {
    this.alerts.on('alert', listener);
  }

  checkSyncFreshness(now: Date = new Date()): SanctionsSyncAlert | null {
    if (!this.listVersion) {
      return null;
    }
    const syncAgeMs = now.getTime() - this.listVersion.syncedAt.getTime();
    if (syncAgeMs <= this.policy.maxSyncAgeMs) {
      return null;
    }
    const alert: SanctionsSyncAlert = {
      type: 'sanctions_sync_stale',
      source: this.listVersion.source,
      version: this.listVersion.version,
      syncedAt: this.listVersion.syncedAt,
      syncAgeMs,
      maxSyncAgeMs: this.policy.maxSyncAgeMs,
      severity: syncAgeMs > this.policy.maxSyncAgeMs * 2 ? 'critical' : 'warning',
    };
    this.alerts.emit('alert', alert);
    return alert;
  }

  screen(subject: string, matches: (subject: string) => boolean, now: Date = new Date()): SanctionsScreeningResult {
    if (!this.listVersion) {
      throw new Error('Sanctions list has not been synced; cannot screen');
    }
    const syncAgeMs = now.getTime() - this.listVersion.syncedAt.getTime();
    const stale = syncAgeMs > this.policy.maxSyncAgeMs;
    if (stale) {
      this.checkSyncFreshness(now);
    }

    let outcome: SanctionsScreeningSnapshot['outcome'];
    let matched = false;
    if (stale && this.policy.onStaleList === 'block') {
      outcome = 'stale_list';
    } else {
      matched = matches(subject);
      outcome = matched ? 'match' : 'clear';
    }

    return {
      matched,
      snapshot: {
        listSource: this.listVersion.source,
        listVersion: this.listVersion.version,
        listSyncedAt: this.listVersion.syncedAt,
        syncAgeMs,
        stale,
        outcome,
        screenedAt: now,
      },
    };
  }
}
