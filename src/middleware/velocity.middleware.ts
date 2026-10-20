import { Request, Response, NextFunction } from 'express';
import { Redis } from 'ioredis';
import { logger } from '../utils/logger';

/**
 * Velocity limiting middleware.
 *
 * The check-and-increment is performed atomically inside Redis via a Lua
 * script so that concurrent requests cannot both observe a count below the
 * threshold and then both record their event. The counter key carries a TTL
 * equal to the window so stale state expires automatically.
 *
 * Failure policy: fail-closed. If Redis is unavailable or the script errors,
 * the request is rejected rather than allowed through.
 */

let redisClient: Redis | null = null;

function getRedis(): Redis {
  if (!redisClient) {
    redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
    });
    redisClient.on('error', (err) => {
      logger.error('Velocity limiter Redis error', { error: err.message });
    });
  }
  return redisClient;
}

// Atomically: increment the counter, set expiry on first write, and return the
// resulting count. KEYS[1] = counter key, ARGV[1] = window seconds.
const ATOMIC_INCREMENT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
`;

export interface VelocityOptions {
  /** Maximum number of events allowed within the window. */
  limit: number;
  /** Window length in seconds. */
  windowSeconds: number;
  /** Function deriving the counter scope (e.g. user id, ip). */
  keyGenerator?: (req: Request) => string;
  /** Prefix for the Redis key. */
  keyPrefix?: string;
}

function defaultKeyGenerator(req: Request): string {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

/**
 * Atomically evaluates the velocity for the current request and records the
 * event. Returns the count after incrementing, or throws on backend failure.
 */
async function evaluateAndRecord(
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<{ allowed: boolean; count: number }> {
  const redis = getRedis();
  const count = (await redis.eval(
    ATOMIC_INCREMENT_SCRIPT,
    1,
    key,
    String(windowSeconds),
  )) as number;

  return { allowed: count <= limit, count };
}

export function velocityLimiter(options: VelocityOptions) {
  const {
    limit,
    windowSeconds,
    keyGenerator = defaultKeyGenerator,
    keyPrefix = 'velocity',
  } = options;

  return async function velocityMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    const scope = keyGenerator(req);
    const key = `${keyPrefix}:${scope}`;

    try {
      const { allowed, count } = await evaluateAndRecord(key, limit, windowSeconds);

      res.setHeader('X-RateLimit-Limit', String(limit));
      res.setHeader('X-RateLimit-Remaining', String(Math.max(0, limit - count)));

      if (!allowed) {
        res.status(429).json({
          error: 'Too many requests',
          message: 'Velocity limit exceeded. Please try again later.',
        });
        return;
      }

      next();
    } catch (err) {
      // Fail-closed: reject when the atomic check cannot be performed.
      logger.error('Velocity check failed; rejecting request (fail-closed)', {
        error: err instanceof Error ? err.message : String(err),
        key,
      });
      res.status(503).json({
        error: 'Service Unavailable',
        message: 'Unable to verify request velocity. Please try again later.',
      });
    }
  };
}

export default velocityLimiter;
