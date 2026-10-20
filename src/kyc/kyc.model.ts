export interface KycDecisionRecord {
  reasonCodes: string[];
  reviewerId?: string;
  providerId?: string;
  evidenceRefs: string[];
  policyVersion: string;
  decidedAt: Date;
}

export interface KycTransition {
  fromStatus: KycStatus;
  toStatus: KycStatus;
  decision: KycDecisionRecord;
}

export type KycStatus =
  | 'pending'
  | 'in_review'
  | 'approved'
  | 'rejected'
  | 'escalated';

export interface KycRecord {
  id: string;
  userId: string;
  status: KycStatus;
  tier: number;
  transitions: KycTransition[];
  createdAt: Date;
  updatedAt: Date;
}
