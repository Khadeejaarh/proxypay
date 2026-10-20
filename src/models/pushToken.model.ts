import { Schema, model, Document, Model } from 'mongoose';

export type PushPlatform = 'android' | 'ios' | 'web';

export interface PushTokenDocument extends Document {
  userId: string;
  token: string;
  platform: PushPlatform;
  active: boolean;
  deactivatedAt?: Date;
  deactivationReason?: string;
  createdAt: Date;
  updatedAt: Date;
}

const pushTokenSchema = new Schema<PushTokenDocument>(
  {
    userId: { type: String, required: true, index: true },
    token: { type: String, required: true, unique: true },
    platform: {
      type: String,
      required: true,
      enum: ['android', 'ios', 'web'],
      index: true,
    },
    active: { type: Boolean, default: true, index: true },
    deactivatedAt: { type: Date },
    deactivationReason: { type: String },
  },
  { timestamps: true },
);

pushTokenSchema.index({ platform: 1, active: 1 });

export const PushToken: Model<PushTokenDocument> = model<PushTokenDocument>(
  'PushToken',
  pushTokenSchema,
);

/**
 * Firebase Admin messaging error codes that indicate the device token is no
 * longer valid and should not be retried.
 */
export const INVALID_TOKEN_ERROR_CODES = [
  'messaging/registration-token-not-registered',
  'messaging/invalid-registration-token',
  'messaging/invalid-argument',
] as const;

export function isInvalidTokenError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const code = (error as { code?: unknown }).code;
  return (
    typeof code === 'string' &&
    (INVALID_TOKEN_ERROR_CODES as readonly string[]).includes(code)
  );
}

/**
 * Deactivate a token that the provider reported as invalid. The token is kept
 * (not deleted) so it is not retried indefinitely while remaining auditable.
 */
export async function deactivateInvalidToken(
  token: string,
  reason = 'provider-invalid-token',
): Promise<boolean> {
  const result = await PushToken.updateOne(
    { token, active: true },
    { $set: { active: false, deactivatedAt: new Date(), deactivationReason: reason } },
  );
  return result.modifiedCount > 0;
}

export interface PlatformFailureRate {
  platform: PushPlatform;
  total: number;
  failed: number;
  failureRate: number;
}

/**
 * Aggregate provider failure rates by platform. Only counts are returned; token
 * contents are never included in the reported metrics.
 */
export async function getFailureRatesByPlatform(
  failures: Array<{ platform: PushPlatform; failed: boolean }>,
): Promise<PlatformFailureRate[]> {
  const platforms: PushPlatform[] = ['android', 'ios', 'web'];
  return platforms.map((platform) => {
    const scoped = failures.filter((f) => f.platform === platform);
    const total = scoped.length;
    const failed = scoped.filter((f) => f.failed).length;
    return {
      platform,
      total,
      failed,
      failureRate: total === 0 ? 0 : failed / total,
    };
  });
}
