import { Router, Request, Response } from "express";
import { z } from "zod";
import {
  generateToken,
  verifyToken,
  JWTPayload,
  generateRefreshToken,
  verifyRefreshToken,
  createSessionBinding,
  registerJwtSession,
} from "../auth/jwt";
import { v4 as uuidv4 } from "uuid";
import { createSSORouter } from "../auth/sso";
import { createOIDCRouter, initializeOIDCProviders } from "../auth/oidc";
import { enforceSSOForEmployees } from "../middleware/ssoEnforcement";
import { tokenController } from "../controllers/tokenController";
import { authenticateToken } from "../middleware/auth";
import {
  authenticateUser,
  createUser,
  getUserPermissions,
  getUserByPhoneNumber,
  User,
} from "../services/userService";
import { getLockoutStatus, recordFailedAttempt } from "../auth/lockout";
import { verifyTOTPToken, verifyBackupCode, is2FAEnabled } from "../auth/2fa";
import { evaluateAdminLoginAnomaly } from "../services/loginAnomaly";
import { activityTrackingService } from "../services/activityTrackingService";
import { checkDeviceFingerprint } from "../middleware/fingerprint";
import { validateRequest } from "../middleware/validation";
import { hashPassword } from "../utils/password";
import { redisClient } from "../config/redis";
import { TransactionModel } from "../models/transaction";
import { EmailService } from "../services/email";
import {
  loginRateLimiter,
  registerRateLimiter,
} from "../middleware/authRateLimit";
import { ERROR_CODES } from "../constants/errorCodes";
import { createError } from "../middleware/errorHandler";
import { registerSchema } from "../validation/authSchemas";

const emailService = new EmailService();

export const authRoutes = Router();

// Shared with the OpenAPI generator (src/openapi/schemas/auth.ts) so the
// documented constraints always match what this endpoint accepts.
export { registerSchema };

/**
 * POST /api/auth/register
 */
authRoutes.post(
  "/register",
  registerRateLimiter,
  validateRequest(registerSchema),
  async (req: Request, res: Response) => {
    const { phone_number, password } = req.body as z.infer<
      typeof registerSchema
    >;
    try {
      const passwordHash = await hashPassword(password);
      const user = await createUser({
        phone_number,
        password_hash: passwordHash,
      } as any);
      res
        .status(201)
        .json({ message: "User registered successfully", userId: user.id });
    } catch (error) {
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Registration failed", {
        error: "Registration failed",
        message: error instanceof Error ? error.message : "Unknown error",
      });
    }
  },
);

// Initialize OIDC Strategy (Google/Azure)
initializeOIDCProviders();

// Mount SSO routes
authRoutes.use("/sso", createSSORouter());
authRoutes.use("/sso/oidc", createOIDCRouter());

/**
 * POST /api/auth/login
 *
 * Authenticates a user and returns JWT + refresh token.
 * Enforces account lockout after 5 failed attempts within 10 minutes.
 * Sends an email notification when an account is locked.
 */
authRoutes.post(
  "/login",
  loginRateLimiter,
  async (req: Request, res: Response) => {
    const { phone_number } = req.body;

    if (!phone_number) {
      throw createError(ERROR_CODES.MISSING_FIELD, "phone_number is required", {
        error: "Missing required fields",
      });
    }

    // Use the phone number as the lockout identifier.
    const lockoutId = phone_number;

    try {
      // ── 1. Gate: reject immediately if the account is already locked ──────────
      const lockoutStatus = await getLockoutStatus(lockoutId);
      if (lockoutStatus.isLocked) {
        throw createError(
          ERROR_CODES.LIMIT_EXCEEDED,
          `Your account is temporarily locked. ` +
            `Please try again in ${lockoutStatus.minutesRemaining} minute${lockoutStatus.minutesRemaining === 1 ? "" : "s"}.`,
          {
            unlocksAt: lockoutStatus.unlocksAt,
            minutesRemaining: lockoutStatus.minutesRemaining,
            error: "ACCOUNT_LOCKED",
          },
        );
      }

      // ── 2. Attempt authentication ─────────────────────────────────────────────
      const user = await authenticateUser(phone_number);

      if (!user) {
        // ── 3a. Authentication failed: record the attempt ──────────────────────
        const result = await recordFailedAttempt(lockoutId);

        if (result.justLocked) {
          // ── 3b. Account just got locked: send notification email ───────────
          // Best-effort: look up the user's email to notify them.
          try {
            const userRecord = await getUserByPhoneNumber(phone_number);
            const userEmail = (userRecord as any)?.email as string | undefined;
            if (userEmail) {
              void emailService.sendAccountLockoutNotification(userEmail, {
                minutesRemaining: result.lockoutStatus.minutesRemaining ?? 30,
                unlocksAt: result.lockoutStatus.unlocksAt ?? new Date(),
                ipAddress: req.ip,
              });
            }
          } catch (emailErr) {
            console.error(
              "[Login] Failed to send lockout notification:",
              emailErr,
            );
          }

          throw createError(ERROR_CODES.ACCOUNT_LOCKED, result.message, {
            error: "ACCOUNT_LOCKED",
            unlocksAt: result.lockoutStatus.unlocksAt,
            minutesRemaining: result.lockoutStatus.minutesRemaining,
          });
        }

        throw createError(ERROR_CODES.UNAUTHORIZED, result.message, {
          error: "Unauthorized",
          attemptsRemaining: result.lockoutStatus.attemptsRemaining,
        });
      }

      const anomaly = await evaluateAdminLoginAnomaly(req, user);
      const deviceCheck = await checkDeviceFingerprint(req, user.id);
      const suspicious = anomaly.suspicious || deviceCheck.requiresAdditionalVerification;
      const anomalyReason =
        anomaly.reason ??
        (deviceCheck.requiresAdditionalVerification
          ? "Repeated device fingerprint mismatches detected"
          : undefined);

      if (suspicious) {
        if (!is2FAEnabled(user)) {
          throw createError(
            ERROR_CODES.FORBIDDEN,
            "Anomalous login was blocked. Enable two-factor authentication and retry.",
            {
              error: "Suspicious login detected",
              requiresTwoFactor: true,
              anomaly: anomalyReason,
            },
          );
        }

        const twoFactorToken = req.headers["x-2fa-token"] as string | undefined;
        const backupCode = req.body["backupCode"] || req.body["backup_code"];

        let verified2fa = false;

        if (twoFactorToken && user.two_factor_secret) {
          verified2fa = verifyTOTPToken(user.two_factor_secret, twoFactorToken);
        }

        if (!verified2fa && backupCode && user.backup_codes) {
          const backupCodes = user.backup_codes.map((item, index) =>
            typeof item === "string"
              ? {
                  id: String(index),
                  code_hash: item,
                  used: false,
                  created_at: new Date(),
                }
              : item,
          );
          const verification = await verifyBackupCode(backupCode, backupCodes);
          verified2fa = verification.valid;
        }

        if (!verified2fa) {
          throw createError(
            ERROR_CODES.FORBIDDEN,
            "Suspicious login detected. Provide X-2FA-Token header or backupCode to continue.",
            {
              error: "Two-factor authentication required",
              requiresTwoFactor: true,
              anomaly: anomalyReason,
            },
          );
        }
      }

      const payload = {
        userId: user.id,
        email: user.phone_number,
        role: user.role_name || "user",
      };

      const sessionId = uuidv4();
      const binding = createSessionBinding(req.header("X-Device-ID"), req.get("user-agent"));
      const token = generateToken(payload, { sessionId, binding });
      const decodedToken = verifyToken(token);
      await registerJwtSession(user.id, sessionId, binding, decodedToken.exp ?? Math.floor(Date.now() / 1000) + 3600);
      const refreshToken = await generateRefreshToken(user.id, undefined, undefined, { sessionId, binding });
      const permissions = await getUserPermissions(user.id);

      // Track successful login for activity analytics (best-effort, non-blocking).
      void activityTrackingService.trackActivity({
        userId: user.id,
        eventType: "user.login",
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
        metadata: { method: "phone_password" },
      });

      res.json({
        message: "Login successful",
        token,
        refreshToken,
        user: {
          userId: user.id,
          email: user.phone_number,
          role: user.role_name || "user",
          permissions,
        },
      });
    } catch (error) {
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        error instanceof Error ? error.message : "Unknown error",
        { error: "Token generation failed" },
      );
    }
  },
);

/**
 * POST /api/auth/refresh
 *
 * Rotates refresh token, issues new access and refresh tokens, and enforces strict rotation
 */
authRoutes.post("/refresh", async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    throw createError(ERROR_CODES.MISSING_FIELD, "Refresh token is required", {
      error: "Refresh token is required",
    });
  }
  try {
    // Verify and check for reuse
    const decoded = await verifyRefreshToken(refreshToken);
    // Issue new access and refresh tokens (rotate)
    const token = generateToken(
      { userId: decoded.userId, email: "" },
      { sessionId: decoded.sessionId, binding: decoded.binding },
    );
    if (decoded.sessionId && decoded.binding) {
      const decodedToken = verifyToken(token);
      await registerJwtSession(decoded.userId, decoded.sessionId, decoded.binding, decodedToken.exp ?? Math.floor(Date.now() / 1000) + 3600);
    }
    const newRefreshToken = await generateRefreshToken(
      decoded.userId,
      decoded.familyId,
      decoded.tokenId,
      decoded.sessionId && decoded.binding
        ? { sessionId: decoded.sessionId, binding: decoded.binding }
        : undefined,
    );
    res.json({
      message: "Token rotation successful",
      token,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    throw createError(
      ERROR_CODES.UNAUTHORIZED,
      error instanceof Error ? error.message : "Unknown error",
      {
        error: "Refresh failed",
      },
    );
  }
});

/**
 * GET /api/auth/tokens
 *
 * List all active refresh token
 */
authRoutes.get(
  "/tokens/active/:family_id",
  authenticateToken,
  tokenController.findAll,
);

/**
 * DELETE /api/auth/tokens
 *
 * Delete all refresh token
 */
authRoutes.delete(
  "/tokens/revoke-all/:family_id",
  authenticateToken,
  tokenController.revokeAll,
);

/**
 * DELETE /api/auth/tokens
 *
 * Delete a specific refresh token
 */
authRoutes.delete(
  "/tokens/:token_id/:family_id",
  authenticateToken,
  tokenController.revoke,
);

/**
 * POST /api/auth/verify
 *
 * Verify a JWT token and return the decoded payload
 */
authRoutes.post("/verify", (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    throw createError(
      ERROR_CODES.MISSING_FIELD,
      "Token is required for verification",
      {
        error: "Missing token",
      },
    );
  }

  try {
    const payload = verifyToken(token);
    res.json({
      valid: true,
      payload,
    });
  } catch (error) {
    throw createError(
      ERROR_CODES.UNAUTHORIZED,
      error instanceof Error ? error.message : "Unknown error",
      {
        error: "Token verification failed",
      },
    );
  }
});

/**
 * GET /api/auth/me
 *
 * Protected route that returns current user information
 * Requires valid JWT token in Authorization header
 */
authRoutes.get(
  "/me",
  authenticateToken,
  async (req: Request, res: Response) => {
    const payload = req.jwtUser as JWTPayload;

    if (!payload) {
      throw createError(ERROR_CODES.MISSING_FIELD, "No token provided", {
        error: "Access denied",
      });
    }

    try {
      const permissions = await getUserPermissions(payload.userId);

      const cacheKey = `user:balance:stats:${payload.userId}`;
      let balanceStats = {
        total_deposited: "0",
        total_withdrawn: "0",
        current_balance: "0",
        available_balance: "0",
        pending_balance: "0",
      };

      if (redisClient.isOpen) {
        const cachedStats = await redisClient.get(cacheKey);
        if (cachedStats) {
          try {
            balanceStats = JSON.parse(cachedStats.toString());
          } catch (e) {
            console.error("Error parsing cached balance stats", e);
          }
        } else {
          const transactionModel = new TransactionModel();
          const dbStats = await transactionModel.getBalanceStatistics(
            payload.userId,
          );
          if (dbStats) {
            balanceStats = {
              total_deposited: dbStats.total_deposited || "0",
              total_withdrawn: dbStats.total_withdrawn || "0",
              current_balance: dbStats.current_balance || "0",
              available_balance: dbStats.available_balance || "0",
              pending_balance: dbStats.pending_balance || "0",
            };
            await redisClient.set(cacheKey, JSON.stringify(balanceStats), {
              EX: 3600,
            });
          }
        }
      } else {
        const transactionModel = new TransactionModel();
        const dbStats = await transactionModel.getBalanceStatistics(
          payload.userId,
        );
        if (dbStats) {
          balanceStats = {
            total_deposited: dbStats.total_deposited || "0",
            total_withdrawn: dbStats.total_withdrawn || "0",
            current_balance: dbStats.current_balance || "0",
            available_balance: dbStats.available_balance || "0",
            pending_balance: dbStats.pending_balance || "0",
          };
        }
      }

      res.json({
        user: {
          userId: payload.userId,
          email: payload.email,
          role: payload.role,
          permissions,
          total_deposited: balanceStats.total_deposited,
          total_withdrawn: balanceStats.total_withdrawn,
          current_balance: balanceStats.current_balance,
          available_balance: balanceStats.available_balance,
          pending_balance: balanceStats.pending_balance,
        },
        tokenInfo: {
          issuedAt: payload.iat,
          expiresAt: payload.exp,
        },
      });
    } catch (error) {
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Unable to fetch user info",
        {
          error: "Unable to fetch user info",
          message: error instanceof Error ? error.message : "Unknown error",
        },
      );
    }
  },
);
