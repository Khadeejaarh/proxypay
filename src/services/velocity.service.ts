import { Redis } from 'ioredis';

/**
 * Velocity service.
 *
 * Velocity checks must be atomic across concurrent requests: evaluating the
 * current count and recording the new event has to happen as a single
 * operation, otherwise two parallel requests can both observe a count below
 * the threshold and both pass.
 *
 * We use a Redis Lua script so the read-check-increment happens atomically on
 * the server. Counters carry a TTL so stale state expires automatically.
 *
 * Failure policy: fail-closed. If Redis errors out we reject the request
 * rather than silently allowing it through.
 */

export interface VelocityRule {
  /** Logical name of the rule, e.g. "card_attempts". */
  name: string;
  /** Maximum number of events allowed within the window. */
  limit: number;
  /** Window length in seconds. */
  windowSeconds: number;
}

export interface VelocityCheckResult {
  allowed: boolean;
  /** Count observed after the atomic increment (including this event). */
  count: number;
  limit: number;
  /** Seconds until the counter expires. */
  ttlSeconds: number;
}

export class VelocityError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'VelocityError';
  }
}

/**
 * Atomically increments the counter for `key` and returns the new value plus
 * the remaining TTL. If the key does not exist it is created with the window
 * TTL. The TTL is only set on creation so the window does not slide on every
 * event (fixed-window semantics).
 */
const ATOMIC_INCREMENT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return { current, ttl }
`;

export class VelocityService {
  private readonly scriptSha: Promise<string>;

  constructor(private readonly redis: Redis) {
    this.scriptSha = this.redis.script('LOAD', ATOMIC_INCREMENT_SCRIPT) as unknown as Promise<string>;
  }

  private buildKey(rule: VelocityRule, subject: string): string {
    return `velocity:${rule.name}:${subject}`;
  }

  /**
   * Atomically evaluate and record a velocity event for `subject`.
   *
   * Returns whether the event is allowed under `rule`. The event is always
   * recorded (even when it exceeds the limit) so that repeated attempts keep
   * counting against the window.
   *
   * Throws {@link VelocityError} on Redis failure (fail-closed).
   */
  async checkAndRecord(rule: VelocityRule, subject: string): Promise<VelocityCheckResult> {
    const key = this.buildKey(rule, subject);

    let raw: [number, number];
    try {
      raw = (await this.evalScript(key, rule.windowSeconds)) as [number, number];
    } catch (err) {
      // Fail-closed: never allow a request through when we cannot verify it.
      throw new VelocityError(
        `Velocity check failed for rule "${rule.name}"`,
        err,
      );
    }

    const count = Number(raw[0]);
    const ttl = Number(raw[1]);

    return {
      allowed: count <= rule.limit,
      count,
      limit: rule.limit,
      ttlSeconds: ttl > 0 ? ttl : rule.windowSeconds,
    };
  }

  private async evalScript(key: string, windowSeconds: number): Promise<unknown> {
    const sha = await this.scriptSha;
    try {
      return await this.redis.evalsha(sha, 1, key, String(windowSeconds));
    } catch (err) {
      // Script may have been flushed from the cache; reload and retry once.
      if (err instanceof Error && err.message.includes('NOSCRIPT')) {
        const reloaded = (await this.redis.script('LOAD', ATOMIC_INCREMENT_SCRIPT)) as unknown as string;
        return this.redis.evalsha(reloaded, 1, key, String(windowSeconds));
      }
      throw err;
    }
  }
}
