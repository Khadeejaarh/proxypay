import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, EntityManager } from 'typeorm';
import { User } from '../users/user.entity';
import { Order } from '../orders/order.entity';
import { Payment } from '../payments/payment.entity';
import { AuditLog } from '../audit/audit-log.entity';
import { GdprPurgePreview } from './gdpr-purge-preview.entity';
import { GdprPurgeExecution } from './gdpr-purge-execution.entity';

/**
 * Tables and external objects that a user-data purge touches.
 * Shared by both the dry-run preview and the real purge so the two
 * can never drift apart.
 */
const PURGE_TARGETS: ReadonlyArray<{
  name: string;
  count: (manager: EntityManager, userId: string) => Promise<number>;
  purge: (manager: EntityManager, userId: string) => Promise<number>;
}> = [
  {
    name: 'orders',
    count: (manager, userId) =>
      manager.count(Order, { where: { userId } }),
    purge: async (manager, userId) => {
      const result = await manager.delete(Order, { userId });
      return result.affected ?? 0;
    },
  },
  {
    name: 'payments',
    count: (manager, userId) =>
      manager.count(Payment, { where: { userId } }),
    purge: async (manager, userId) => {
      const result = await manager.delete(Payment, { userId });
      return result.affected ?? 0;
    },
  },
  {
    name: 'audit_logs',
    count: (manager, userId) =>
      manager.count(AuditLog, { where: { userId } }),
    purge: async (manager, userId) => {
      const result = await manager.delete(AuditLog, { userId });
      return result.affected ?? 0;
    },
  },
  {
    name: 'user',
    count: (manager, userId) =>
      manager.count(User, { where: { id: userId } }),
    purge: async (manager, userId) => {
      const result = await manager.delete(User, { id: userId });
      return result.affected ?? 0;
    },
  },
];

@Injectable()
export class GdprRepository {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(GdprPurgePreview)
    private readonly previewRepository: Repository<GdprPurgePreview>,
    @InjectRepository(GdprPurgeExecution)
    private readonly executionRepository: Repository<GdprPurgeExecution>,
    private readonly dataSource: DataSource,
  ) {}

  /**
   * Read-only dry-run: counts affected records across the same tables and
   * external objects used by purge, without deleting anything. Persists the
   * preview so it can be confirmed and later linked to an execution.
   */
  async previewPurge(userId: string): Promise<GdprPurgePreview> {
    const counts: Record<string, number> = {};
    let total = 0;

    for (const target of PURGE_TARGETS) {
      const count = await target.count(this.dataSource.manager, userId);
      counts[target.name] = count;
      total += count;
    }

    const preview = this.previewRepository.create({
      userId,
      counts,
      totalRecords: total,
      confirmedAt: null,
    });

    return this.previewRepository.save(preview);
  }

  /**
   * Executes the irreversible purge. Requires an explicit confirmation and a
   * previously generated preview ID; the execution is linked to its preview
   * for audit/traceability.
   */
  async executePurge(
    userId: string,
    previewId: string,
    confirmed: boolean,
  ): Promise<GdprPurgeExecution> {
    if (!confirmed) {
      throw new Error('Purge execution requires explicit confirmation');
    }

    const preview = await this.previewRepository.findOne({
      where: { id: previewId, userId },
    });
    if (!preview) {
      throw new Error(`Purge preview ${previewId} not found for user ${userId}`);
    }

    return this.dataSource.transaction(async (manager) => {
      const counts: Record<string, number> = {};
      let total = 0;

      for (const target of PURGE_TARGETS) {
        const affected = await target.purge(manager, userId);
        counts[target.name] = affected;
        total += affected;
      }

      preview.confirmedAt = new Date();
      await manager.save(preview);

      const execution = manager.create(GdprPurgeExecution, {
        userId,
        previewId: preview.id,
        counts,
        totalRecords: total,
      });

      return manager.save(execution);
    });
  }
}
