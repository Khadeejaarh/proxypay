import { getMessaging, Message, MulticastMessage } from 'firebase-admin/messaging';
import { PushToken, PushTokenPlatform } from '../models/pushToken.model';
import { logger } from '../utils/logger';

const INVALID_TOKEN_ERROR_CODES = new Set([
  'messaging/registration-token-not-registered',
  'messaging/invalid-registration-token',
  'messaging/invalid-argument',
]);

export interface PushFailureMetrics {
  platform: PushTokenPlatform;
  attempted: number;
  failed: number;
  failureRate: number;
}

export interface PushDeliveryResult {
  successCount: number;
  failureCount: number;
  prunedTokenCount: number;
  failuresByPlatform: PushFailureMetrics[];
}

export class NotificationService {
  async sendPushToTokens(
    tokens: PushToken[],
    payload: Omit<Message, 'token'>,
  ): Promise<PushDeliveryResult> {
    const result: PushDeliveryResult = {
      successCount: 0,
      failureCount: 0,
      prunedTokenCount: 0,
      failuresByPlatform: [],
    };

    if (tokens.length === 0) {
      return result;
    }

    const attemptedByPlatform = new Map<PushTokenPlatform, number>();
    const failedByPlatform = new Map<PushTokenPlatform, number>();
    const tokenPlatform = new Map<string, PushTokenPlatform>();

    for (const token of tokens) {
      attemptedByPlatform.set(
        token.platform,
        (attemptedByPlatform.get(token.platform) ?? 0) + 1,
      );
      tokenPlatform.set(token.token, token.platform);
    }

    const message: MulticastMessage = {
      ...payload,
      tokens: tokens.map((t) => t.token),
    };

    const response = await getMessaging().sendEachForMulticast(message);

    const invalidTokens: string[] = [];

    response.responses.forEach((sendResponse, index) => {
      const token = tokens[index];
      if (sendResponse.success) {
        result.successCount += 1;
        return;
      }

      result.failureCount += 1;
      const platform = tokenPlatform.get(token.token) ?? token.platform;
      failedByPlatform.set(platform, (failedByPlatform.get(platform) ?? 0) + 1);

      const errorCode = sendResponse.error?.code;
      if (errorCode && INVALID_TOKEN_ERROR_CODES.has(errorCode)) {
        invalidTokens.push(token.token);
      }

      // Log provider error code only; never log token contents.
      logger.warn('Push delivery failed', {
        platform,
        errorCode: errorCode ?? 'unknown',
      });
    });

    if (invalidTokens.length > 0) {
      await PushToken.updateMany(
        { token: { $in: invalidTokens } },
        { $set: { active: false, deactivatedAt: new Date() } },
      );
      result.prunedTokenCount = invalidTokens.length;
    }

    for (const [platform, attempted] of attemptedByPlatform.entries()) {
      const failed = failedByPlatform.get(platform) ?? 0;
      result.failuresByPlatform.push({
        platform,
        attempted,
        failed,
        failureRate: attempted > 0 ? failed / attempted : 0,
      });
    }

    return result;
  }
}
