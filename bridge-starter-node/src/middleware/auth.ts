import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { config } from "../config/env";

/**
 * Stable machine-readable error codes for the auth middleware.
 * These codes are part of the public API contract and must not change
 * across API versions.
 */
export enum AuthErrorCode {
  MISSING_SIGNATURE = "MISSING_SIGNATURE",
  INVALID_SIGNATURE = "INVALID_SIGNATURE",
  SERVER_MISCONFIGURED = "SERVER_MISCONFIGURED",
}

/**
 * Typed error for expected domain failures. Forwarded to the shared error
 * middleware via `next(err)` so status/code mapping stays centralized.
 */
export class AuthError extends Error {
  public readonly code: AuthErrorCode;
  public readonly status: number;

  constructor(code: AuthErrorCode, status: number, message: string) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    this.status = status;
  }
}

function getRawBody(req: Request): Buffer {
  // body parsers can attach a raw body buffer to the request (app.ts config).
  // Fallback to JSON.stringify for environments that don't provide rawBody.
  const anyReq = req as any;
  if (anyReq.rawBody && Buffer.isBuffer(anyReq.rawBody)) {
    return anyReq.rawBody as Buffer;
  }

  // If no rawBody is available, fall back to stable string encoding of req.body
  try {
    return Buffer.from(JSON.stringify(req.body));
  } catch (e) {
    return Buffer.from("");
  }
}

export const verifyWebhookSignature = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const signatureHeader = (req.headers["x-bridge-signature"] ||
    req.headers["x-bridge-signature-256"]) as string | undefined;

  if (!signatureHeader) {
    return next(
      new AuthError(
        AuthErrorCode.MISSING_SIGNATURE,
        401,
        "Missing signature header",
      ),
    );
  }

  if (!config.webhookSecret) {
    console.error("WEBHOOK_SECRET not configured; rejecting webhook request");
    return next(
      new AuthError(
        AuthErrorCode.SERVER_MISCONFIGURED,
        500,
        "Server misconfigured",
      ),
    );
  }

  const raw = getRawBody(req);
  const expected = crypto
    .createHmac("sha256", config.webhookSecret)
    .update(raw)
    .digest("hex");

  try {
    const sigBuf = Buffer.from(signatureHeader, "utf8");
    const expectedBuf = Buffer.from(expected, "utf8");
    if (
      sigBuf.length === expectedBuf.length &&
      crypto.timingSafeEqual(sigBuf, expectedBuf)
    ) {
      return next();
    }
  } catch (e) {
    // fall through to unauthorized below
  }

  return next(
    new AuthError(AuthErrorCode.INVALID_SIGNATURE, 401, "Invalid signature"),
  );
};

/**
 * SEP-10 challenge validation and replay protection.
 *
 * Enforces:
 *  - home domain (manage_data name/value and web_auth_domain)
 *  - server account / signer
 *  - time bounds (minTime/maxTime)
 *  - single-use semantics via a consumed-challenge cache (Redis-backed when
 *    available, in-memory fallback otherwise)
 */

const CHALLENGE_TTL_SECONDS = 15 * 60;

// In-memory fallback cache for consumed challenge IDs.
const consumedChallenges = new Map<string, number>();

function pruneConsumed(now: number) {
  for (const [id, expiresAt] of consumedChallenges) {
    if (expiresAt <= now) {
      consumedChallenges.delete(id);
    }
  }
}

function getRedisClient(): any | null {
  const anyConfig = config as any;
  if (anyConfig.redisClient) {
    return anyConfig.redisClient;
  }
  return null;
}

/**
 * Atomically mark a challenge ID as consumed. Returns true if the ID was
 * newly consumed, false if it was already used (replay).
 */
async function consumeChallengeId(id: string): Promise<boolean> {
  const redis = getRedisClient();
  if (redis && typeof redis.set === "function") {
    try {
      const result = await redis.set(
        `sep10:challenge:${id}`,
        "1",
        "EX",
        CHALLENGE_TTL_SECONDS,
        "NX",
      );
      return result === "OK";
    } catch (e) {
      console.error("Redis error while consuming SEP-10 challenge", e);
      // Fail closed: reject if we cannot guarantee single-use.
      return false;
    }
  }

  const now = Date.now();
  pruneConsumed(now);
  if (consumedChallenges.has(id)) {
    return false;
  }
  consumedChallenges.set(id, now + CHALLENGE_TTL_SECONDS * 1000);
  return true;
}

export interface Sep10ChallengeOperation {
  type: string;
  name?: string;
  value?: string;
  source_account?: string;
}

export interface Sep10Challenge {
  id: string;
  sourceAccount: string;
  operations: Sep10ChallengeOperation[];
  minTime: number;
  maxTime: number;
  signatures: Array<{ key: string; valid: boolean }>;
}

export interface Sep10ValidationOptions {
  homeDomain: string;
  serverAccount: string;
  webAuthDomain?: string;
  now?: number;
}

export type Sep10ValidationResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Validate a parsed SEP-10 challenge transaction against the configured
 * home domain, server account, time bounds, and single-use semantics.
 */
export async function validateSep10Challenge(
  challenge: Sep10Challenge,
  options: Sep10ValidationOptions,
): Promise<Sep10ValidationResult> {
  const { homeDomain, serverAccount, webAuthDomain } = options;
  const now = options.now ?? Math.floor(Date.now() / 1000);

  if (!challenge || !challenge.id) {
    return { ok: false, reason: "Missing challenge id" };
  }

  // Server account must be the transaction source.
  if (challenge.sourceAccount !== serverAccount) {
    return { ok: false, reason: "Challenge source account mismatch" };
  }

  // Time bounds must be present and currently valid.
  if (!challenge.minTime || !challenge.maxTime) {
    return { ok: false, reason: "Challenge missing time bounds" };
  }
  if (now < challenge.minTime) {
    return { ok: false, reason: "Challenge not yet valid" };
  }
  if (now > challenge.maxTime) {
    return { ok: false, reason: "Challenge expired" };
  }

  // Must be signed by the configured server account.
  const serverSig = challenge.signatures.find(
    (sig) => sig.key === serverAccount && sig.valid,
  );
  if (!serverSig) {
    return { ok: false, reason: "Challenge not signed by server account" };
  }

  const ops = challenge.operations || [];
  if (ops.length === 0) {
    return { ok: false, reason: "Challenge has no operations" };
  }

  // Validate every operation against the configured home domain.
  for (const op of ops) {
    if (op.type !== "manage_data") {
      return { ok: false, reason: `Unexpected operation type: ${op.type}` };
    }
    if (op.source_account && op.source_account !== serverAccount) {
      return { ok: false, reason: "Operation source account mismatch" };
    }

    if (op.name === `${homeDomain} auth`) {
      // manage_data name must be "<homeDomain> auth" and value non-empty.
      if (!op.value) {
        return { ok: false, reason: "Missing challenge value" };
      }
    } else if (op.name === "web_auth_domain") {
      const expected = webAuthDomain || homeDomain;
      if (op.value !== expected) {
        return { ok: false, reason: "web_auth_domain mismatch" };
      }
    } else {
      return { ok: false, reason: `Unexpected manage_data name: ${op.name}` };
    }
  }

  // Enforce single-use semantics; reject replays.
  const consumed = await consumeChallengeId(challenge.id);
  if (!consumed) {
    return { ok: false, reason: "Challenge already used" };
  }

  return { ok: true };
}

export default verifyWebhookSignature;
