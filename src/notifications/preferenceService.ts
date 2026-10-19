export type NotificationChannel = 'email' | 'sms' | 'push' | 'whatsapp';

export type DeliveryOutcome = 'delivered' | 'failed' | 'skipped';

export interface ChannelPreference {
  channel: NotificationChannel;
  enabled: boolean;
  consent: boolean;
}

export interface RecipientPreferences {
  recipientId: string;
  channels: ChannelPreference[];
  /** Ordered fallback chain the recipient is willing to receive. */
  fallbackOrder: NotificationChannel[];
}

export interface ChannelAttempt {
  channel: NotificationChannel;
  outcome: DeliveryOutcome;
  /** Machine-readable failure reason when outcome is 'failed'. */
  reason?: string;
  attemptedAt: Date;
}

/**
 * Failure classification that drives the fallback-vs-retry policy.
 *
 * - transient: retry the same channel (network blips, provider 5xx, throttling).
 * - permanent: do not retry; fall back to the next consented channel
 *   (invalid address, invalid push token, unsubscribed, hard bounce).
 * - consent: recipient has not consented / opted out; skip channel entirely,
 *   never retry and never fall back to it.
 */
export type FailureKind = 'transient' | 'permanent' | 'consent';

export interface FallbackDecision {
  action: 'retry' | 'fallback' | 'stop';
  channel?: NotificationChannel;
  reason: string;
}

const TRANSIENT_REASONS = new Set([
  'timeout',
  'rate_limited',
  'provider_unavailable',
  'network_error',
]);

const PERMANENT_REASONS = new Set([
  'invalid_address',
  'invalid_push_token',
  'hard_bounce',
  'unsubscribed',
  'blocked',
]);

const CONSENT_REASONS = new Set(['no_consent', 'opted_out']);

export function classifyFailure(reason: string): FailureKind {
  if (CONSENT_REASONS.has(reason)) return 'consent';
  if (PERMANENT_REASONS.has(reason)) return 'permanent';
  if (TRANSIENT_REASONS.has(reason)) return 'transient';
  // Unknown failures are treated as transient so we retry before giving up.
  return 'transient';
}

/**
 * Returns the channels the recipient has both enabled and consented to,
 * preserving the recipient's declared fallback order.
 */
export function eligibleChannels(prefs: RecipientPreferences): NotificationChannel[] {
  const byChannel = new Map(prefs.channels.map((c) => [c.channel, c]));
  const ordered = prefs.fallbackOrder.length
    ? prefs.fallbackOrder
    : prefs.channels.map((c) => c.channel);

  return ordered.filter((channel) => {
    const pref = byChannel.get(channel);
    return !!pref && pref.enabled && pref.consent;
  });
}

/**
 * Decides what to do after a channel attempt fails, honoring recipient
 * preferences/consent and the explicit retry-vs-fallback policy.
 */
export function decideFallback(
  prefs: RecipientPreferences,
  failedChannel: NotificationChannel,
  reason: string,
  retriesSoFar: number,
  maxRetries = 2,
): FallbackDecision {
  const kind = classifyFailure(reason);

  if (kind === 'consent') {
    return { action: 'stop', reason: `consent_denied:${reason}` };
  }

  if (kind === 'transient' && retriesSoFar < maxRetries) {
    return { action: 'retry', channel: failedChannel, reason };
  }

  const eligible = eligibleChannels(prefs);
  const currentIndex = eligible.indexOf(failedChannel);
  const next = currentIndex >= 0 ? eligible[currentIndex + 1] : eligible[0];

  if (next && next !== failedChannel) {
    return { action: 'fallback', channel: next, reason };
  }

  return { action: 'stop', reason: `no_fallback_available:${reason}` };
}

/**
 * Records a per-channel delivery attempt so routing decisions are auditable.
 */
export class DeliveryAttemptLog {
  private readonly attempts: ChannelAttempt[] = [];

  record(channel: NotificationChannel, outcome: DeliveryOutcome, reason?: string): ChannelAttempt {
    const attempt: ChannelAttempt = { channel, outcome, reason, attemptedAt: new Date() };
    this.attempts.push(attempt);
    return attempt;
  }

  forRecipient(): ChannelAttempt[] {
    return [...this.attempts];
  }
}
