export type NotificationChannel = 'email' | 'sms' | 'push' | 'whatsapp';

export type DeliveryOutcome = 'delivered' | 'retryable_failure' | 'permanent_failure';

export interface ChannelAttempt {
  channel: NotificationChannel;
  outcome: DeliveryOutcome;
  error?: string;
  attemptedAt: Date;
}

export interface RecipientPreferences {
  /** Channels the recipient has opted into. */
  enabledChannels: NotificationChannel[];
  /** Channels the recipient has explicitly consented to receive. */
  consentedChannels: NotificationChannel[];
  /** Ordered preference of channels; earlier entries are preferred. */
  preferredOrder?: NotificationChannel[];
}

export interface NotificationMessage {
  recipientId: string;
  subject: string;
  body: string;
}

export interface ChannelSender {
  send(channel: NotificationChannel, message: NotificationMessage): Promise<void>;
}

export interface AttemptStore {
  record(recipientId: string, attempt: ChannelAttempt): Promise<void>;
}

export interface PreferenceService {
  getPreferences(recipientId: string): Promise<RecipientPreferences>;
}

/**
 * Explicit fallback policy: which failures trigger fallback to the next
 * channel versus a retry on the same channel.
 *
 * - retryable_failure: transient (timeout, 5xx, rate limit) -> retry same channel
 * - permanent_failure: invalid recipient/token, hard bounce, unsubscribed -> fallback
 */
export const FALLBACK_POLICY: Record<DeliveryOutcome, 'retry' | 'fallback' | 'stop'> = {
  delivered: 'stop',
  retryable_failure: 'retry',
  permanent_failure: 'fallback',
};

const DEFAULT_ORDER: NotificationChannel[] = ['push', 'email', 'sms', 'whatsapp'];

const RETRYABLE_ERROR_PATTERNS = [
  /timeout/i,
  /timed out/i,
  /rate.?limit/i,
  /throttl/i,
  /5\d\d/,
  /temporar/i,
  /unavailable/i,
  /network/i,
];

const PERMANENT_ERROR_PATTERNS = [
  /invalid/i,
  /not.?registered/i,
  /unsubscrib/i,
  /opt.?out/i,
  /bounce/i,
  /blocked/i,
  /no.?consent/i,
  /4\d\d/,
];

export function classifyFailure(error: unknown): DeliveryOutcome {
  const message = error instanceof Error ? error.message : String(error ?? '');
  if (PERMANENT_ERROR_PATTERNS.some((p) => p.test(message))) {
    return 'permanent_failure';
  }
  if (RETRYABLE_ERROR_PATTERNS.some((p) => p.test(message))) {
    return 'retryable_failure';
  }
  // Unknown failures default to retryable so transient issues are not dropped.
  return 'retryable_failure';
}

export interface NotificationRouterOptions {
  sender: ChannelSender;
  preferences: PreferenceService;
  attempts: AttemptStore;
  maxRetries?: number;
}

export class NotificationRouter {
  private readonly sender: ChannelSender;
  private readonly preferences: PreferenceService;
  private readonly attempts: AttemptStore;
  private readonly maxRetries: number;

  constructor(options: NotificationRouterOptions) {
    this.sender = options.sender;
    this.preferences = options.preferences;
    this.attempts = options.attempts;
    this.maxRetries = options.maxRetries ?? 1;
  }

  /**
   * Resolve the ordered list of channels to try, honoring recipient
   * preferences and consent. Channels without consent are never used.
   */
  async resolveChannels(recipientId: string): Promise<NotificationChannel[]> {
    const prefs = await this.preferences.getPreferences(recipientId);
    const consented = new Set(prefs.consentedChannels);
    const enabled = new Set(prefs.enabledChannels);
    const order = prefs.preferredOrder ?? DEFAULT_ORDER;

    return order.filter((channel) => consented.has(channel) && enabled.has(channel));
  }

  /**
   * Route a message across channels, persisting every per-channel attempt and
   * applying the explicit fallback/retry policy.
   */
  async route(message: NotificationMessage): Promise<ChannelAttempt[]> {
    const channels = await this.resolveChannels(message.recipientId);
    const history: ChannelAttempt[] = [];

    for (const channel of channels) {
      let retries = 0;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const attempt = await this.attempt(channel, message);
        history.push(attempt);
        await this.attempts.record(message.recipientId, attempt);

        const decision = FALLBACK_POLICY[attempt.outcome];
        if (decision === 'stop') {
          return history;
        }
        if (decision === 'retry' && retries < this.maxRetries) {
          retries += 1;
          continue;
        }
        // 'fallback' or exhausted retries -> move to next channel.
        break;
      }
    }

    return history;
  }

  private async attempt(
    channel: NotificationChannel,
    message: NotificationMessage,
  ): Promise<ChannelAttempt> {
    try {
      await this.sender.send(channel, message);
      return { channel, outcome: 'delivered', attemptedAt: new Date() };
    } catch (error) {
      return {
        channel,
        outcome: classifyFailure(error),
        error: error instanceof Error ? error.message : String(error),
        attemptedAt: new Date(),
      };
    }
  }
}
