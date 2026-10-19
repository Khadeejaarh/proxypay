import { randomUUID } from "crypto";

/**
 * Channel-account provisioning with secret protection.
 *
 * Signing secrets are NEVER persisted in plaintext. They are handed to a
 * managed secret store (KMS / secret manager) and only an opaque reference is
 * kept on the channel-account record. Provisioning requires an explicit
 * approval and is bounded by funding limits.
 */

export interface SecretStore {
  /** Persist secret material in the managed store and return an opaque reference. */
  putSecret(name: string, secret: string): Promise<string>;
  /** Resolve a reference back to secret material at signing time. */
  getSecret(reference: string): Promise<string>;
  /** Remove secret material (used during rotation/retirement). */
  deleteSecret(reference: string): Promise<void>;
}

export interface ChannelAccountRecord {
  id: string;
  publicKey: string;
  /** Reference into the managed secret store — never the secret itself. */
  secretRef: string;
  status: "pending_approval" | "active" | "retired";
  fundingLimitStroops: string;
  fundedStroops: string;
  createdAt: string;
  approvedBy?: string;
  approvedAt?: string;
}

export interface ChannelAccountRepository {
  save(record: ChannelAccountRecord): Promise<void>;
  findById(id: string): Promise<ChannelAccountRecord | null>;
  list(): Promise<ChannelAccountRecord[]>;
}

export interface ProvisioningRequest {
  publicKey: string;
  /** Raw signing secret — consumed by the secret store, never persisted here. */
  signingSecret: string;
  fundingLimitStroops: string;
  requestedBy: string;
}

export interface ApprovalContext {
  approverId: string;
  /** Admin RBAC role required to approve provisioning. */
  role: string;
}

export interface FundingContext {
  /** Amount the operator intends to fund at provisioning time, in stroops. */
  amountStroops: string;
}

export interface ChannelAccountServiceDeps {
  secretStore: SecretStore;
  repository: ChannelAccountRepository;
  /** Maximum funding allowed per channel account, in stroops. */
  maxFundingStroops: string;
  /** RBAC role permitted to approve channel-account provisioning. */
  approverRole?: string;
}

export class ProvisioningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProvisioningError";
  }
}

const DEFAULT_APPROVER_ROLE = "channel_account_admin";

function toBigInt(value: string, field: string): bigint {
  try {
    return BigInt(value);
  } catch {
    throw new ProvisioningError(`Invalid ${field}: ${value}`);
  }
}

export class ChannelAccountService {
  private readonly secretStore: SecretStore;
  private readonly repository: ChannelAccountRepository;
  private readonly maxFundingStroops: bigint;
  private readonly approverRole: string;

  constructor(deps: ChannelAccountServiceDeps) {
    this.secretStore = deps.secretStore;
    this.repository = deps.repository;
    this.maxFundingStroops = toBigInt(deps.maxFundingStroops, "maxFundingStroops");
    this.approverRole = deps.approverRole ?? DEFAULT_APPROVER_ROLE;
  }

  /**
   * Create a channel account in a pending state. The signing secret is moved
   * into the managed secret store immediately; only its reference is kept.
   */
  async requestProvisioning(request: ProvisioningRequest): Promise<ChannelAccountRecord> {
    if (!request.publicKey) {
      throw new ProvisioningError("publicKey is required");
    }
    if (!request.signingSecret) {
      throw new ProvisioningError("signingSecret is required");
    }

    const fundingLimit = toBigInt(request.fundingLimitStroops, "fundingLimitStroops");
    if (fundingLimit <= 0n) {
      throw new ProvisioningError("fundingLimitStroops must be positive");
    }
    if (fundingLimit > this.maxFundingStroops) {
      throw new ProvisioningError(
        `fundingLimitStroops ${fundingLimit} exceeds maximum ${this.maxFundingStroops}`,
      );
    }

    const id = randomUUID();
    const secretRef = await this.secretStore.putSecret(
      `stellar/channel-accounts/${id}`,
      request.signingSecret,
    );

    const record: ChannelAccountRecord = {
      id,
      publicKey: request.publicKey,
      secretRef,
      status: "pending_approval",
      fundingLimitStroops: fundingLimit.toString(),
      fundedStroops: "0",
      createdAt: new Date().toISOString(),
    };

    await this.repository.save(record);
    return record;
  }

  /**
   * Approve a pending channel account. Requires an admin RBAC role and
   * enforces the funding limit before the account becomes active.
   */
  async approveProvisioning(
    id: string,
    approval: ApprovalContext,
    funding: FundingContext,
  ): Promise<ChannelAccountRecord> {
    if (approval.role !== this.approverRole) {
      throw new ProvisioningError(
        `Approver role '${approval.role}' is not permitted to approve provisioning`,
      );
    }

    const record = await this.repository.findById(id);
    if (!record) {
      throw new ProvisioningError(`Channel account ${id} not found`);
    }
    if (record.status !== "pending_approval") {
      throw new ProvisioningError(`Channel account ${id} is not pending approval`);
    }

    const amount = toBigInt(funding.amountStroops, "amountStroops");
    if (amount < 0n) {
      throw new ProvisioningError("amountStroops must not be negative");
    }
    const limit = toBigInt(record.fundingLimitStroops, "fundingLimitStroops");
    if (amount > limit) {
      throw new ProvisioningError(
        `Funding ${amount} exceeds channel-account limit ${limit}`,
      );
    }

    const updated: ChannelAccountRecord = {
      ...record,
      status: "active",
      fundedStroops: amount.toString(),
      approvedBy: approval.approverId,
      approvedAt: new Date().toISOString(),
    };

    await this.repository.save(updated);
    return updated;
  }

  /**
   * Rotate the signing secret for an active channel account. The new secret is
   * stored in the managed store and the old reference is retired.
   */
  async rotateSecret(id: string, newSigningSecret: string): Promise<ChannelAccountRecord> {
    if (!newSigningSecret) {
      throw new ProvisioningError("newSigningSecret is required");
    }

    const record = await this.repository.findById(id);
    if (!record) {
      throw new ProvisioningError(`Channel account ${id} not found`);
    }

    const newRef = await this.secretStore.putSecret(
      `stellar/channel-accounts/${id}/rotated-${Date.now()}`,
      newSigningSecret,
    );

    const updated: ChannelAccountRecord = { ...record, secretRef: newRef };
    await this.repository.save(updated);

    await this.secretStore.deleteSecret(record.secretRef);
    return updated;
  }

  /** Resolve the signing secret for an active account at signing time. */
  async getSigningSecret(id: string): Promise<string> {
    const record = await this.repository.findById(id);
    if (!record) {
      throw new ProvisioningError(`Channel account ${id} not found`);
    }
    if (record.status !== "active") {
      throw new ProvisioningError(`Channel account ${id} is not active`);
    }
    return this.secretStore.getSecret(record.secretRef);
  }
}
