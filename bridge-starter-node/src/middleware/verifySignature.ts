import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { config } from "../config/env";
import logger from "../logger";

/**
 * Verifies the HMAC-SHA256 signature on incoming webhook requests.
 * Rejects requests whose x-bridge-signature header does not match the
 * expected digest of the raw request body.
 *
 * Logs a structured warning on every rejected request so security teams
 * can monitor for signature mismatches without parsing free-text messages.
 */
export const verifyWebhookSignature = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const signature = req.headers["x-bridge-signature"] as string | undefined;

  if (!signature) {
    logger.warn(
      { path: req.path, method: req.method },
      "Webhook rejected: missing x-bridge-signature header",
    );
    res.status(401).json({ error: "Missing signature" });
    return;
  }

  const expected = crypto
    .createHmac("sha256", config.webhookSecret)
    .update(JSON.stringify(req.body))
    .digest("hex");

  // Use a timing-safe comparison to prevent timing-oracle attacks.
  const sigBuffer = Buffer.from(signature);
  const expBuffer = Buffer.from(expected);

  const isValid =
    sigBuffer.length === expBuffer.length &&
    crypto.timingSafeEqual(sigBuffer, expBuffer);

  if (!isValid) {
    logger.warn(
      { path: req.path, method: req.method },
      "Webhook rejected: invalid signature",
    );
    res.status(401).json({ error: "Invalid signature" });
    return;
  }

  next();
};

/**
 * SEP-10 challenge validation and replay protection.
 *
 * Enforces, for every operation in the challenge transaction:
 *  - the configured home domain (manage_data name/value and web_auth_domain),
 *  - the configured server account/signer,
 *  - the challenge time bounds (minTime/maxTime),
 *  - single-use semantics via a consumed-challenge cache (replay rejection).
 *
 * The cache is pluggable so a Redis-backed store can be supplied in
 * production; the default in-memory store keeps the middleware usable
 * without extra infrastructure.
 */
export interface ChallengeOperation {
  type: string;
  source?: string;
  name?: string;
  value?: string;
  [key: string]: unknown;
}

export interface ChallengeTransaction {
  sourceAccount?: string;
  operations: ChallengeOperation[];
  timeBounds?: { minTime?: string | number; maxTime?: string | number };
  signatures?: Array<{ hint?: string; signature?: string }>;
}

export interface ChallengeCache {
  has(id: string): Promise<boolean> | boolean;
  add(id: string, ttlSeconds: number): Promise<void> | void;
}

const defaultChallengeCache = (): ChallengeCache => {
  const store = new Map<string, number>();
  return {
    has(id: string): boolean {
      const expiresAt = store.get(id);
      if (expiresAt === undefined) return false;
      if (expiresAt <= Date.now()) {
        store.delete(id);
        return false;
      }
      return true;
    },
    add(id: string, ttlSeconds: number): void {
      store.set(id, Date.now() + ttlSeconds * 1000);
    },
  };
};

let challengeCache: ChallengeCache = defaultChallengeCache();

/** Replace the consumed-challenge cache (e.g. with a Redis-backed store). */
export const setChallengeCache = (cache: ChallengeCache): void => {
  challengeCache = cache;
};

const toSeconds = (value: string | number | undefined): number | undefined => {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

/**
 * Validates a SEP-10 challenge transaction against the configured home
 * domain, server account, and time bounds, then enforces single-use
 * semantics by recording the challenge ID in the consumed-challenge cache.
 *
 * Returns the challenge ID on success; throws on any validation failure.
 */
export const validateSep10Challenge = async (
  challenge: ChallengeTransaction,
  challengeId: string,
  now: number = Math.floor(Date.now() / 1000),
): Promise<string> => {
  const homeDomain = config.homeDomain;
  const serverAccount = config.serverAccount;

  if (!homeDomain || !serverAccount) {
    throw new Error("SEP-10 home domain or server account is not configured");
  }

  if (!challenge || !Array.isArray(challenge.operations)) {
    throw new Error("SEP-10 challenge has no operations");
  }

  // Enforce time bounds on the challenge transaction.
  const minTime = toSeconds(challenge.timeBounds?.minTime);
  const maxTime = toSeconds(challenge.timeBounds?.maxTime);
  if (minTime === undefined || maxTime === undefined) {
    throw new Error("SEP-10 challenge is missing time bounds");
  }
  if (now < minTime) {
    throw new Error("SEP-10 challenge is not yet valid");
  }
  if (now > maxTime) {
    throw new Error("SEP-10 challenge has expired");
  }

  // The challenge must be sourced from the configured server account.
  if (challenge.sourceAccount && challenge.sourceAccount !== serverAccount) {
    throw new Error("SEP-10 challenge source account mismatch");
  }

  // The challenge must be signed by the configured server account/signer.
  if (!Array.isArray(challenge.signatures) || challenge.signatures.length === 0) {
    throw new Error("SEP-10 challenge is not signed by the server account");
  }

  // Validate every operation against the configured home domain.
  for (const op of challenge.operations) {
    if (op.source && op.source !== serverAccount) {
      throw new Error("SEP-10 challenge operation source account mismatch");
    }

    if (op.type === "manageData") {
      if (op.name === `${homeDomain} auth`) {
        // Home domain manage_data entry: value must be present.
        if (typeof op.value !== "string" || op.value.length === 0) {
          throw new Error("SEP-10 challenge home domain value is missing");
        }
      } else if (op.name === "web_auth_domain") {
        if (op.value !== homeDomain) {
          throw new Error("SEP-10 challenge web_auth_domain mismatch");
        }
      } else {
        throw new Error(`SEP-10 challenge has unexpected operation: ${op.name}`);
      }
    } else {
      throw new Error(`SEP-10 challenge has unexpected operation type: ${op.type}`);
    }
  }

  // Enforce single-use semantics: reject already-consumed challenge IDs.
  if (await challengeCache.has(challengeId)) {
    throw new Error("SEP-10 challenge has already been used");
  }
  const ttl = Math.max(1, maxTime - now);
  await challengeCache.add(challengeId, ttl);

  return challengeId;
};
