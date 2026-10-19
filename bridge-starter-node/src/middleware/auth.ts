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

export default verifyWebhookSignature;
