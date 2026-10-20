export type NotificationChannel = 'email' | 'sms' | 'push' | 'whatsapp';

export type DeliveryOutcome =
  | 'delivered'
  | 'failed_transient'
  | 'failed_permanent'
  | 'skipped_no_consent'
  | 'skipped_preference';

/**
 * Explicit policy for how a failed attempt should be handled.
 * - retry: transient failure on the same channel; retry before considering fallback.
 * - fallback: permanent failure (or exhausted retries); move to the next preferred channel.
 * - none: do not retry or fall back (e.g. missing consent, invalid recipient).
 */
export type FailureAction = 'retry' | 'fallback' | 'none';

export interface ChannelAttempt {
  channel: NotificationChannel;
  outcome: DeliveryOutcome;
  /** Provider/transport error code when outcome is a failure. */
  errorCode?: string;
  /** Number of attempts made on this channel for this notification. */
  attempts: number;
  attemptedAt: string;
}

export interface RecipientPreferences {
  /** Channels the recipient has opted into, in preferred order. */
  preferredChannels: NotificationChannel[];
  /** Channels the recipient has explicitly consented to receive. */
  consentedChannels: NotificationChannel[];
}

export interface NotificationDeliveryRecord {
  notificationId: string;
  recipientId: string;
  /** Ordered per-channel attempts, persisted for audit and fallback decisions. */
  attempts: ChannelAttempt[];
  /** Channel that ultimately delivered the notification, if any. */
  deliveredChannel?: NotificationChannel;
}

/**
 * Classify a delivery outcome into an explicit failure action so routing
 * consistently decides between retry and fallback.
 */
export function resolveFailureAction(outcome: DeliveryOutcome): FailureAction {
  switch (outcome) {
    case 'delivered':
      return 'none';
    case 'failed_transient':
      return 'retry';
    case 'failed_permanent':
      return 'fallback';
    case 'skipped_no_consent':
    case 'skipped_preference':
      return 'none';
    default:
      return 'none';
  }
}

/**
 * Select the ordered channels to attempt, honoring recipient preferences and
 * consent. Channels without consent are excluded; preferred order is preserved.
 */
export function selectChannels(prefs: RecipientPreferences): NotificationChannel[] {
  const consented = new Set(prefs.consentedChannels);
  const ordered = prefs.preferredChannels.filter((channel) => consented.has(channel));
  return ordered;
}
