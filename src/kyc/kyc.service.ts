import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { KycRecord } from './entities/kyc-record.entity';
import { KycTransition } from './entities/kyc-transition.entity';
import { KycStatus } from './enums/kyc-status.enum';
import { KycTier } from './enums/kyc-tier.enum';
import { AuditService } from '../audit/audit.service';

export interface KycDecisionContext {
  reasonCode: string;
  actorId?: string;
  actorType?: 'reviewer' | 'provider' | 'system';
  provider?: string;
  evidenceRefs?: string[];
  policyVersion: string;
  metadata?: Record<string, unknown>;
}

@Injectable()
export class KycService {
  private readonly logger = new Logger(KycService.name);

  constructor(
    @InjectRepository(KycRecord)
    private readonly kycRepository: Repository<KycRecord>,
    @InjectRepository(KycTransition)
    private readonly transitionRepository: Repository<KycTransition>,
    private readonly auditService: AuditService,
  ) {}

  async getRecord(userId: string): Promise<KycRecord | null> {
    return this.kycRepository.findOne({ where: { userId } });
  }

  async submitForReview(
    userId: string,
    context: KycDecisionContext,
  ): Promise<KycRecord> {
    return this.transition(userId, KycStatus.PENDING, context);
  }

  async approve(
    userId: string,
    context: KycDecisionContext,
  ): Promise<KycRecord> {
    return this.transition(userId, KycStatus.APPROVED, context);
  }

  async reject(
    userId: string,
    context: KycDecisionContext,
  ): Promise<KycRecord> {
    return this.transition(userId, KycStatus.REJECTED, context);
  }

  async upgradeTier(
    userId: string,
    tier: KycTier,
    context: KycDecisionContext,
  ): Promise<KycRecord> {
    const record = await this.getOrCreateRecord(userId);
    const fromTier = record.tier;
    record.tier = tier;
    record.updatedAt = new Date();
    const saved = await this.kycRepository.save(record);

    await this.recordTransition(saved, {
      fromStatus: saved.status,
      toStatus: saved.status,
      fromTier,
      toTier: tier,
      context,
    });

    return saved;
  }

  async handleProviderWebhook(
    userId: string,
    status: KycStatus,
    context: KycDecisionContext,
  ): Promise<KycRecord> {
    return this.transition(userId, status, {
      ...context,
      actorType: context.actorType ?? 'provider',
    });
  }

  async handleDocumentUpload(
    userId: string,
    documentRef: string,
    context: KycDecisionContext,
  ): Promise<KycRecord> {
    const record = await this.getOrCreateRecord(userId);
    const evidenceRefs = Array.from(
      new Set([...(context.evidenceRefs ?? []), documentRef]),
    );
    record.updatedAt = new Date();
    const saved = await this.kycRepository.save(record);

    await this.recordTransition(saved, {
      fromStatus: saved.status,
      toStatus: saved.status,
      fromTier: saved.tier,
      toTier: saved.tier,
      context: { ...context, evidenceRefs },
    });

    return saved;
  }

  private async transition(
    userId: string,
    toStatus: KycStatus,
    context: KycDecisionContext,
  ): Promise<KycRecord> {
    const record = await this.getOrCreateRecord(userId);
    const fromStatus = record.status;
    record.status = toStatus;
    record.updatedAt = new Date();
    const saved = await this.kycRepository.save(record);

    await this.recordTransition(saved, {
      fromStatus,
      toStatus,
      fromTier: saved.tier,
      toTier: saved.tier,
      context,
    });

    return saved;
  }

  private async getOrCreateRecord(userId: string): Promise<KycRecord> {
    let record = await this.kycRepository.findOne({ where: { userId } });
    if (!record) {
      record = this.kycRepository.create({
        userId,
        status: KycStatus.NOT_STARTED,
        tier: KycTier.TIER_0,
      });
      record = await this.kycRepository.save(record);
    }
    return record;
  }

  private async recordTransition(
    record: KycRecord,
    params: {
      fromStatus: KycStatus;
      toStatus: KycStatus;
      fromTier: KycTier;
      toTier: KycTier;
      context: KycDecisionContext;
    },
  ): Promise<KycTransition> {
    const { fromStatus, toStatus, fromTier, toTier, context } = params;

    const transition = this.transitionRepository.create({
      kycRecordId: record.id,
      userId: record.userId,
      fromStatus,
      toStatus,
      fromTier,
      toTier,
      reasonCode: context.reasonCode,
      actorId: context.actorId ?? null,
      actorType: context.actorType ?? 'system',
      provider: context.provider ?? null,
      evidenceRefs: context.evidenceRefs ?? [],
      policyVersion: context.policyVersion,
      metadata: context.metadata ?? null,
    });

    const savedTransition = await this.transitionRepository.save(transition);

    await this.auditService.record({
      action: 'kyc.transition',
      subjectId: record.userId,
      actorId: context.actorId ?? null,
      actorType: context.actorType ?? 'system',
      reasonCode: context.reasonCode,
      policyVersion: context.policyVersion,
      evidenceRefs: context.evidenceRefs ?? [],
      metadata: {
        transitionId: savedTransition.id,
        fromStatus,
        toStatus,
        fromTier,
        toTier,
        provider: context.provider ?? null,
      },
    });

    this.logger.log(
      `KYC transition ${record.userId}: ${fromStatus} -> ${toStatus} (reason=${context.reasonCode}, policy=${context.policyVersion})`,
    );

    return savedTransition;
  }
}
