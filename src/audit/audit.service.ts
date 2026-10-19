import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditRecord } from './audit-record.entity';

export interface KycDecisionInput {
  entityType: string;
  entityId: string;
  transition: string;
  reasonCode?: string;
  actorId?: string;
  actorType?: 'reviewer' | 'provider' | 'system';
  provider?: string;
  evidenceRefs?: string[];
  policyVersion?: string;
  metadata?: Record<string, unknown>;
}

@Injectable()
  export class AuditService {
  constructor(
    @InjectRepository(AuditRecord)
    private readonly auditRepository: Repository<AuditRecord>,
  ) {}

  async recordKycDecision(input: KycDecisionInput): Promise<AuditRecord> {
    const record = this.auditRepository.create({
      entityType: input.entityType,
      entityId: input.entityId,
      action: input.transition,
      reasonCode: input.reasonCode ?? null,
      actorId: input.actorId ?? null,
      actorType: input.actorType ?? null,
      provider: input.provider ?? null,
      evidenceRefs: input.evidenceRefs ?? [],
      policyVersion: input.policyVersion ?? null,
      metadata: input.metadata ?? {},
    });

    return this.auditRepository.save(record);
  }

  async findKycDecisions(entityType: string, entityId: string): Promise<AuditRecord[]> {
    return this.auditRepository.find({
      where: { entityType, entityId },
      order: { createdAt: 'ASC' },
    });
  }
}
