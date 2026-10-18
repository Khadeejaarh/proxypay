/**
 * WebSocket session revalidation (issue #814).
 *
 * A WebSocket (or graphql-ws subscription) outlives a single HTTP request, so
 * a token that was valid at handshake time can be revoked (password change,
 * logout, admin action) while the socket stays open. This module centralises:
 *
 *  - a per-connection session registry tracking userId + token expiry,
 *  - expiry-based termination (checked on heartbeat),
 *  - Redis pub/sub so a revocation on one instance terminates that user's
 *    sockets on every instance.
 *
 * Revocation writes `user:{id}:jwt_invalidated_at` (see flushUserSessions in
 * src/config/redis.ts) and is mirrored onto channel `ws.auth.revoked`.
 */

import type { RedisClientType } from "redis";

/** Redis channel used to fan out auth revocations to all instances. */
export const WS_REVOCATION_CHANNEL = "ws.auth.revoked";

/** Close code used for policy violations (RFC 6455). */
export const WS_AUTH_POLICY_VIOLATION = 1008;

/** Message used when a connection is closed because auth was revoked. */
export const WS_REVOKED_MESSAGE = "Authentication revoked";

/** Payload published on WS_REVOCATION_CHANNEL. */
export interface AuthRevocationEvent {
  userId: string;
  sessionId?: string | null;
  /** Optional: revoke only a single session instead of all user sessions. */
  reason?: string;
}

/** A tracked, authenticated connection. */
export interface TrackedSession {
  userId: string;
  /** Unix seconds (from the JWT `exp` claim); null when the token has no exp. */
  tokenExpiresAt: number | null;
  sessionId: string | null;
  close: (code?: number, reason?: string) => void;
}

/**
 * Registry of authenticated connections, indexed by userId, with the token
 * expiry needed for periodic revalidation.
 */
export class WsSessionRegistry {
  private sessions = new Map<string, Set<TrackedSession>>();
  private revokedUserIds = new Set<string>();
  private reaperTimer: ReturnType<typeof setInterval> | null = null;

  /** Interval (ms) for the automatic expiry reaper. Overridable for tests. */
  reaperIntervalMs = 30_000;

  /**
   * Starts a periodic expiry reaper if one is not already running. The timer
   * is unref'd so it never keeps the process (or a Jest worker) alive.
   */
  ensureReaper(): void {
    if (this.reaperTimer) return;
    this.reaperTimer = setInterval(() => {
      this.reapExpired();
    }, this.reaperIntervalMs);
    this.reaperTimer.unref?.();
  }

  stopReaper(): void {
    if (this.reaperTimer) {
      clearInterval(this.reaperTimer);
      this.reaperTimer = null;
    }
  }

  add(session: TrackedSession): void {
    let set = this.sessions.get(session.userId);
    if (!set) {
      set = new Set();
      this.sessions.set(session.userId, set);
    }
    set.add(session);
  }

  remove(session: TrackedSession): void {
    const set = this.sessions.get(session.userId);
    if (!set) return;
    set.delete(session);
    if (set.size === 0) this.sessions.delete(session.userId);
  }

  /** Number of tracked sessions for a user (0 when none). */
  countFor(userId: string): number {
    return this.sessions.get(userId)?.size ?? 0;
  }

  /** Total tracked sessions across all users. */
  get size(): number {
    let total = 0;
    for (const set of this.sessions.values()) total += set.size;
    return total;
  }

  /**
   * Terminates every session belonging to `userId` (optionally narrowed to a
   * single sessionId) and marks the user revoked so connections that race in
   * during the same tick are still rejected.
   */
  revokeUser(userId: string, sessionId?: string | null): number {
    this.revokedUserIds.add(userId);
    const set = this.sessions.get(userId);
    if (!set) return 0;

    let terminated = 0;
    for (const session of [...set]) {
      if (sessionId && session.sessionId !== sessionId) continue;
      session.close(WS_AUTH_POLICY_VIOLATION, WS_REVOKED_MESSAGE);
      this.remove(session);
      terminated += 1;
    }
    return terminated;
  }

  /** Whether a user is currently marked revoked (blocks new connections). */
  isRevoked(userId: string): boolean {
    return this.revokedUserIds.has(userId);
  }

  /** Clears the revoked marker (e.g. after the user re-authenticates). */
  clearRevoked(userId: string): void {
    this.revokedUserIds.delete(userId);
  }

  /**
   * Heartbeat-time revalidation: terminates sessions whose token has expired.
   * Returns the number of sessions terminated.
   */
  reapExpired(nowSeconds: number = Math.floor(Date.now() / 1000)): number {
    let terminated = 0;
    for (const set of [...this.sessions.values()]) {
      for (const session of [...set]) {
        if (session.tokenExpiresAt !== null && session.tokenExpiresAt <= nowSeconds) {
          session.close(WS_AUTH_POLICY_VIOLATION, "Token expired");
          this.remove(session);
          terminated += 1;
        }
      }
    }
    return terminated;
  }

  /** Clears all state (used on shutdown). */
  clear(): void {
    this.sessions.clear();
    this.revokedUserIds.clear();
  }
}

/** Process-wide registry so both WS surfaces share revocation state. */
export const wsSessionRegistry = new WsSessionRegistry();

/**
 * Publishes a revocation event so every instance terminates the user's
 * sockets. No-op when Redis is unavailable.
 */
export async function publishAuthRevocation(
  publisher: RedisClientType | null | undefined,
  event: AuthRevocationEvent,
): Promise<void> {
  if (!publisher?.isOpen) return;
  try {
    await publisher.publish(WS_REVOCATION_CHANNEL, JSON.stringify(event));
  } catch (err) {
    console.warn("Failed to publish WS auth revocation:", err);
  }
}

/**
 * Handles an incoming revocation event (called by each instance's Redis
 * subscriber). Returns the number of local sessions terminated.
 */
export function handleAuthRevocation(event: AuthRevocationEvent): number {
  if (!event?.userId) return 0;
  return wsSessionRegistry.revokeUser(event.userId, event.sessionId ?? null);
}

/** Extracts the token expiry (Unix seconds) from a decoded JWT payload. */
export function tokenExpiryFromClaims(claims: {
  exp?: number;
}): number | null {
  return typeof claims.exp === "number" && claims.exp > 0 ? claims.exp : null;
}

/** Extracts the sessionId from a decoded JWT payload. */
export function sessionIdFromClaims(claims: {
  sessionId?: string;
}): string | null {
  return typeof claims.sessionId === "string" ? claims.sessionId : null;
}
