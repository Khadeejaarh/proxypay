import { getMessaging, Message, MulticastMessage } from 'firebase-admin/messaging';
import { logger } from '../utils/logger';

/**
 * Push token record as stored in the push token model.
 * Tokens are deactivated (not deleted) when the provider reports them invalid.
 */
export interface PushTokenRecord {
  token: string;
  platform: PushPlatform;
  active: boolean;
}

export type PushPlatform = 'android' | 'ios' | 'web';

/**
 * Aggregated delivery metrics per platform. Never contains token contents.
 */
export interface PlatformFailureMetrics {
  attempted: number;
  failed: number;
  invalidTokens: number;
  failureRate: number;
}

export type FailureMetricsByPlatform = Record<PushPlatform, PlatformFailureMetrics>;

/**
 * Minimal persistence contract for the push token model. Implementations
 * should mark the token inactive rather than removing the row.
 */
export interface PushTokenStore {
  deactivate(token: string): Promise<void>;
}

const INVALID_TOKEN_ERROR_CODES = new Set<string>([
  'messaging/registration-token-not-registered',
  'messaging/invalid-registration-token',
]);

function emptyMetrics(): PlatformFailureMetrics {
  return { attempted: 0, failed: 0, invalidTokens: 0, failureRate: 0 };
}

function createEmptyMetricsByPlatform(): FailureMetricsByPlatform {
  return {
    android: emptyMetrics(),
    ios: emptyMetrics(),
    web: emptyMetrics(),
  };
}

function isInvalidTokenError(code: string | undefined): boolean {
  return code !== undefined && INVALID_TOKEN_ERROR_CODES.has(code);
}

export class PushService {
  constructor(private readonly tokenStore: PushTokenStore) {}

  /**
   * Sends a multicast push message and prunes tokens the provider reports as
   * invalid. Returns aggregated failure metrics by platform; token contents are
   * never included in the returned metrics or logs.
   */
  async sendMulticast(
    message: Omit<MulticastMessage, 'tokens'>,
    tokens: PushTokenRecord[],
  ): Promise<FailureMetricsByPlatform> {
    const metrics = createEmptyMetricsByPlatform();

    if (tokens.length === 0) {
      return metrics;
    }

    for (const record of tokens) {
      metrics[record.platform].attempted += 1;
    }

    const response = await getMessaging().sendEachForMulticast({
      ...message,
      tokens: tokens.map((record) => record.token),
    });

    const invalidTokens: string[] = [];

    response.responses.forEach((result, index) => {
      const record = tokens[index];
      if (!record) {
        return;
      }

      if (result.success) {
        return;
      }

      const platformMetrics = metrics[record.platform];
      platformMetrics.failed += 1;

      const code = result.error?.code;
      if (isInvalidTokenError(code)) {
        platformMetrics.invalidTokens += 1;
        invalidTokens.push(record.token);
      }
    });

    for (const platform of Object.keys(metrics) as PushPlatform[]) {
      const platformMetrics = metrics[platform];
      platformMetrics.failureRate =
        platformMetrics.attempted === 0
          ? 0
          : platformMetrics.failed / platformMetrics.attempted;
    }

    if (invalidTokens.length > 0) {
      await this.deactivateInvalidTokens(invalidTokens);
    }

    return metrics;
  }

  /**
   * Sends a single push message, pruning the token if the provider reports it
   * invalid. Returns whether delivery succeeded.
   */
  async sendToToken(
    message: Omit<Message, 'token'>,
    record: PushTokenRecord,
  ): Promise<boolean> {
    try {
      await getMessaging().send({ ...message, token: record.token });
      return true;
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (isInvalidTokenError(code)) {
        await this.deactivateInvalidTokens([record.token]);
      } else {
        logger.warn('Push delivery failed', { platform: record.platform, code });
      }
      return false;
    }
  }

  private async deactivateInvalidTokens(tokens: string[]): Promise<void> {
    await Promise.all(
      tokens.map(async (token) => {
        try {
          await this.tokenStore.deactivate(token);
        } catch (error) {
          logger.error('Failed to deactivate invalid push token', {
            error: (error as Error).message,
          });
        }
      }),
    );
  }
}
