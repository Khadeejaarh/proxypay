import { Router, Request, Response, NextFunction } from "express";
import * as StellarSdk from "stellar-sdk";
import { generateToken } from "../auth/jwt";
import {
  updateAdminNotesHandler,
  refundTransactionHandler,
} from "../controllers/transactionController";
import {
  DashboardConfig,
  validateDashboardConfig,
  DASHBOARD_CONFIG_VALIDATION_ERRORS,
  reorderWidgets,
  toggleWidgetVisibility,
  setWidgetRefreshRate,
} from "../utils/dashboardConfig";
import { auditInterceptor } from "../middleware/auditInterceptor";
import { authenticateToken } from "../middleware/auth";
import { requirePermission } from "../middleware/rbac";
import {
  rateLimitExport,
  rateLimitListQueries,
  RATE_LIMIT_CONFIG,
} from "../middleware/rateLimit";
import { MobileMoneyService } from "../services/mobilemoney/mobileMoneyService";
import { getQueueStats } from "../queue/transactionQueue";
import { redisClient } from "../config/redis";
import {
  checkReplicaHealth,
  pool,
  getConnectionPoolStatistics,
  setReplicaEnabled,
  getReplicaStatuses,
} from "../config/database";
import { UserModel } from "../models/users";
import { TransactionModel, TransactionStatus } from "../models/transaction";
import { StellarService, ClawbackDestinationError } from "../services/stellar/stellarService";
import { ledgerService } from "../services/ledgerService";
import highThroughputService from "../services/stellar/highThroughputService";
import multer from "multer";
import { parseCSV, reconcileTransactions } from "../services/csvReconciliation";
import { ProviderReconciliationService } from "../services/providerReconciliationService";
import {
  getTransactionResolutionPercentiles,
  getDisputeResolutionPercentiles,
  getTransactionResolutionTrends,
  getDisputeResolutionTrends,
} from "../services/metrics";
import { queryDLQ, replayDLQEntry } from "../queue/dlq";
import {
  triggerManualTransfer,
  getLiquidityTransfers,
} from "../services/liquidityTransferService";
import {
  ComplianceDocumentModel,
  ComplianceDocumentStatus,
  ComplianceDocumentCreateInput,
  ComplianceDocumentUpdateInput,
} from "../models/complianceDocument";
import { providerSettingsService } from "../services/providerSettingsService";
import { resetCircuitBreakerForProvider } from "../utils/circuitBreaker";
import { ERROR_CODES } from "../constants/errorCodes";
import { createError } from "../middleware/errorHandler";
import { logBulkAdminAudit, searchAuditLogs } from "../utils/log-audit-event";

const router = Router();
const IMPERSONATION_TOKEN_EXPIRES_IN = "15m";
const IMPERSONATION_TOKEN_TTL_MS = 15 * 60 * 1000;
const READ_ONLY_IMPERSONATION_MESSAGE = "Read-only mode active";

router.use(auditInterceptor(pool));

// Multer configuration for CSV uploads
const csvUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (_req, file, cb) => {
    if (
      file.mimetype === "text/csv" ||
      file.mimetype === "application/vnd.ms-excel" ||
      file.originalname.endsWith(".csv")
    ) {
      cb(null, true);
    } else {
      cb(new Error("Only CSV files are allowed"));
    }
  },
});

interface User {
  id: string;
  role: string;
  locked?: boolean;
  dashboard_config?: DashboardConfig;
  [key: string]: unknown;
}

interface Transaction {
  id: string;
  [key: string]: unknown;
}

interface AuthRequest extends Request {
  user?: User;
}

type BulkActionResult = {
  userId: string;
  status: "success" | "failed";
  message?: string;
};

type BulkTransactionActionResult = {
  transactionId: string;
  status: "success" | "failed";
  message?: string;
};

const normalizeBulkIds = (value: unknown): string[] => {
  if (!Array.isArray(value)) return [];

  const ids = value
    .filter((id): id is string => typeof id === "string")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);

  return Array.from(new Set(ids));
};

const MAX_BULK_IDS = 100;

/**
 * Mock services (replace with real DB/services)
 */
const users: User[] = [];
const transactionModel = new TransactionModel();
const complianceDocumentModel = new ComplianceDocumentModel();

const isAdminRole = (role?: string) =>
  role === "admin" || role === "super-admin";

const isSuperAdminRole = (role?: string) => role === "super-admin";

const buildAuditContext = (req: Request) => {
  const authReq = req as AuthRequest;

  return {
    actorUserId: authReq.user?.id,
    actorRole: authReq.user?.role,
    method: req.method,
    path: req.originalUrl,
    ip: req.ip,
    userAgent: req.get("user-agent"),
    timestamp: new Date().toISOString(),
  };
};

const logImpersonationAuditEvent = (
  event:
    | "IMPERSONATION_TOKEN_ISSUED"
    | "IMPERSONATION_TOKEN_DENIED"
    | "IMPERSONATION_TOKEN_REJECTED",
  req: Request,
  details: Record<string, unknown>,
) => {
  console.log("[ADMIN IMPERSONATION]", {
    event,
    ...buildAuditContext(req),
    ...details,
  });
};

/**
 * Middleware: Require Admin Role
 */
export const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
  // Assume req.user is set by auth middleware
  const user = (req as AuthRequest).user;

  if (!user || !isAdminRole(user.role)) {
    throw createError(ERROR_CODES.FORBIDDEN, "Admin access required", {
      message: "Admin access required",
    });
  }

  next();
};

const requireSuperAdmin = (req: Request, res: Response, next: NextFunction) => {
  const user = (req as AuthRequest).user;

  if (!user || !isSuperAdminRole(user.role)) {
    logImpersonationAuditEvent("IMPERSONATION_TOKEN_DENIED", req, {
      reason: "super_admin_required",
    });
    throw createError(ERROR_CODES.FORBIDDEN, "Super-admin access required", {
      message: "Super-admin access required",
    });
  }

  next();
};

/**
 * Middleware: Admin Logger
 */
export const logAdminAction = (action: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    console.log(`[ADMIN ACTION] ${action}`, {
      adminId: (req as AuthRequest).user?.id,
      method: req.method,
      path: req.originalUrl,
      body: req.body,
      timestamp: new Date().toISOString(),
    });
    next();
  };
};

/**
 * Persist a bulk admin operation to the `audit_logs` table (issue #620).
 *
 * `logAdminAction` only writes to stdout, so bulk operations previously left no
 * durable, queryable record of which records were touched or what changed. The
 * write is fire-and-forget: auditing must never fail the operation itself.
 *
 * @param req          Request the operation is running in (supplies actor, IP
 *                     and User-Agent).
 * @param action       Action identifier, e.g. `BULK_FREEZE_USERS`.
 * @param resource     Resource type the action applied to (`user`/`transaction`).
 * @param resourceIds  IDs the operation was applied to.
 * @param changes      Structured description of the change.
 * @param reason       Operator-supplied justification, when required.
 */
const recordBulkAudit = (
  req: Request,
  action: string,
  resource: string,
  resourceIds: string[],
  changes: Record<string, unknown> = {},
  reason?: string,
): void => {
  const actor = (req as AuthRequest).user;

  void logBulkAdminAudit({
    adminId: actor?.id ?? "unknown_admin",
    action,
    resource,
    resourceIds,
    changes: { ...changes, actorRole: actor?.role ?? null },
    reason,
    ipAddress: req.ip ?? null,
    userAgent: req.get("user-agent") ?? null,
  });
};

/** Split a bulk action result set into the ids that succeeded / failed. */
const splitBulkResults = <T extends { status: "success" | "failed" }>(
  results: T[],
  getId: (result: T) => string,
) => ({
  succeededIds: results.filter((r) => r.status === "success").map(getId),
  failedIds: results.filter((r) => r.status === "failed").map(getId),
});

/**
 * Helper: Pagination
 */
const paginate = <T>(data: T[], page: number, limit: number) => {
  const start = (page - 1) * limit;
  const end = start + limit;

  return {
    data: data.slice(start, end),
    pagination: {
      total: data.length,
      page,
      limit,
      totalPages: Math.ceil(data.length / limit),
    },
  };
};

/**
 * =========================
 * METRICS
 * =========================
 */

// GET /api/admin/metrics/transactions/resolution
router.get(
  "/metrics/transactions/resolution",
  requireAdmin,
  logAdminAction("GET_TRANSACTION_RESOLUTION_METRICS"),
  async (req: Request, res: Response) => {
    try {
      const daysBack = parseInt(req.query.days as string) || 30;
      const metrics = await getTransactionResolutionPercentiles(daysBack);
      const trends = await getTransactionResolutionTrends(7);

      res.json({
        metrics,
        trends,
        period: `${daysBack} days`,
        sla_threshold_ms: 24 * 60 * 60 * 1000,
        sla_threshold_hours: 24,
      });
    } catch (err) {
      console.error("Error fetching transaction resolution metrics:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to retrieve transaction resolution metrics",
        {
          message: err instanceof Error ? err.message : "Unknown error",
        },
      );
    }
  },
);

// POST /api/admin/users/bulk/freeze
router.post(
  "/users/bulk/freeze",
  requireAdmin,
  logAdminAction("BULK_FREEZE_USERS"),
  async (req: Request, res: Response) => {
    try {
      const adminUser = (req as AuthRequest).user;
      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      const { reason } = req.body;
      if (!reason || typeof reason !== "string" || reason.trim().length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "A reason is required for freezing an account",
          {
            message: "A reason is required for freezing an account",
          },
        );
      }

      const userIds = normalizeBulkIds(req.body?.userIds);
      if (userIds.length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "userIds must be a non-empty array of user IDs",
          {
            message: "userIds must be a non-empty array of user IDs",
          },
        );
      }

      if (userIds.length > MAX_BULK_IDS) {
        throw createError(
          ERROR_CODES.LIMIT_EXCEEDED,
          `Too many userIds supplied (max ${MAX_BULK_IDS})`,
          {
            message: `Too many userIds supplied (max ${MAX_BULK_IDS})`,
          },
        );
      }

      const userModel = new UserModel();
      const results: BulkActionResult[] = [];

      for (const userId of userIds) {
        try {
          const user = await userModel.findById(userId);
          if (!user) {
            results.push({
              userId,
              status: "failed",
              message: "User not found",
            });
            continue;
          }

          if (user.status === "frozen") {
            results.push({
              userId,
              status: "failed",
              message: "User account is already frozen",
            });
            continue;
          }

          const updatedUser = await userModel.updateStatus(
            userId,
            "frozen",
            adminUser.id,
            reason.trim(),
            req.ip,
            req.get("user-agent"),
          );

          if (!updatedUser) {
            results.push({
              userId,
              status: "failed",
              message: "Failed to freeze user account",
            });
            continue;
          }

          results.push({ userId, status: "success" });

          // Terminate the user's open WS/subscription sessions (issue #814)
          await revokeUserSessionsOnStatusChange(userId, "frozen");
        } catch (error) {
          results.push({
            userId,
            status: "failed",
            message: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }

      const { succeededIds, failedIds } = splitBulkResults(
        results,
        (r) => r.userId,
      );

      recordBulkAudit(
        req,
        "BULK_FREEZE_USERS",
        "user",
        succeededIds,
        {
          status: "frozen",
          reason: reason.trim(),
          requestedIds: userIds,
          failedIds,
        },
        reason.trim(),
      );

      const succeeded = results.filter((r) => r.status === "success").length;
      const failed = results.length - succeeded;

      return res.json({
        message: "Bulk freeze completed",
        summary: {
          total: results.length,
          succeeded,
          failed,
        },
        results,
      });
    } catch (error) {
      // Preserve validation errors (e.g. unknown/empty ids) instead of masking them as 500s.
      if ((error as { code?: string })?.code) throw error;
      console.error("Error bulk freezing users:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);

// POST /api/admin/users/bulk/unfreeze
router.post(
  "/users/bulk/unfreeze",
  requireAdmin,
  logAdminAction("BULK_UNFREEZE_USERS"),
  async (req: Request, res: Response) => {
    try {
      const adminUser = (req as AuthRequest).user;
      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      const { reason } = req.body;
      if (!reason || typeof reason !== "string" || reason.trim().length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "A reason is required for unfreezing an account",
          {
            message: "A reason is required for unfreezing an account",
          },
        );
      }

      const userIds = normalizeBulkIds(req.body?.userIds);
      if (userIds.length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "userIds must be a non-empty array of user IDs",
          {
            message: "userIds must be a non-empty array of user IDs",
          },
        );
      }

      if (userIds.length > MAX_BULK_IDS) {
        throw createError(
          ERROR_CODES.LIMIT_EXCEEDED,
          `Too many userIds supplied (max ${MAX_BULK_IDS})`,
          {
            message: `Too many userIds supplied (max ${MAX_BULK_IDS})`,
          },
        );
      }

      const userModel = new UserModel();
      const results: BulkActionResult[] = [];

      for (const userId of userIds) {
        try {
          const user = await userModel.findById(userId);
          if (!user) {
            results.push({
              userId,
              status: "failed",
              message: "User not found",
            });
            continue;
          }

          if (user.status !== "frozen") {
            results.push({
              userId,
              status: "failed",
              message: "User account is not frozen",
            });
            continue;
          }

          const updatedUser = await userModel.updateStatus(
            userId,
            "active",
            adminUser.id,
            reason.trim(),
            req.ip,
            req.get("user-agent"),
          );

          if (!updatedUser) {
            results.push({
              userId,
              status: "failed",
              message: "Failed to unfreeze user account",
            });
            continue;
          }

          results.push({ userId, status: "success" });
        } catch (error) {
          results.push({
            userId,
            status: "failed",
            message: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }

      const { succeededIds, failedIds } = splitBulkResults(
        results,
        (r) => r.userId,
      );

      recordBulkAudit(
        req,
        "BULK_UNFREEZE_USERS",
        "user",
        succeededIds,
        {
          status: "active",
          reason: reason.trim(),
          requestedIds: userIds,
          failedIds,
        },
        reason.trim(),
      );

      const succeeded = results.filter((r) => r.status === "success").length;
      const failed = results.length - succeeded;

      return res.json({
        message: "Bulk unfreeze completed",
        summary: {
          total: results.length,
          succeeded,
          failed,
        },
        results,
      });
    } catch (error) {
      // Preserve validation errors (e.g. unknown/empty ids) instead of masking them as 500s.
      if ((error as { code?: string })?.code) throw error;
      console.error("Error bulk unfreezing users:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);

// GET /api/admin/metrics/disputes/resolution
router.get(
  "/metrics/disputes/resolution",
  requireAdmin,
  logAdminAction("GET_DISPUTE_RESOLUTION_METRICS"),
  async (req: Request, res: Response) => {
    try {
      const daysBack = parseInt(req.query.days as string) || 30;
      const metrics = await getDisputeResolutionPercentiles(daysBack);
      const trends = await getDisputeResolutionTrends(7);

      res.json({
        metrics,
        trends,
        period: `${daysBack} days`,
        sla_threshold_ms: 24 * 60 * 60 * 1000,
        sla_threshold_hours: 24,
      });
    } catch (err) {
      console.error("Error fetching dispute resolution metrics:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to retrieve dispute resolution metrics",
        {
          message: err instanceof Error ? err.message : "Unknown error",
        },
      );
    }
  },
);

/**
 * =========================
 * USERS
 * =========================
 */

// GET /api/admin/users
router.get(
  "/users",
  requireAdmin,
  rateLimitListQueries,
  logAdminAction("LIST_USERS"),
  async (req: Request, res: Response) => {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;

    const result = await new UserModel().list(limit, (page - 1) * limit);
    res.json({
      data: result.users,
      total: result.total,
      page,
      limit,
      totalPages: Math.ceil(result.total / limit),
    });
  },
);
// GET /api/admin/users/:id
router.get(
  "/users/:id",
  requireAdmin,
  logAdminAction("GET_USER"),
  async (req: Request, res: Response) => {
    const user = await new UserModel().findById(req.params.id);

    if (!user) {
      throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
        message: "User not found",
      });
    }

    res.json(user);
  },
);
// POST /api/admin/users/:id/impersonation-token
router.post(
  "/users/:id/impersonation-token",
  requireAdmin,
  requireSuperAdmin,
  (req: Request, res: Response) => {
    const actor = (req as AuthRequest).user;
    const targetUser = users.find((u) => u.id === req.params.id);
    const reason =
      typeof req.body?.reason === "string" ? req.body.reason.trim() : "";

    if (!targetUser) {
      logImpersonationAuditEvent("IMPERSONATION_TOKEN_REJECTED", req, {
        targetUserId: req.params.id,
        reason: "target_user_not_found",
      });
      throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
        message: "User not found",
      });
    }

    if (!actor) {
      logImpersonationAuditEvent("IMPERSONATION_TOKEN_REJECTED", req, {
        targetUserId: targetUser.id,
        reason: "missing_actor_context",
      });
      throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
        message: "Authentication required",
      });
    }

    if (actor.id === targetUser.id) {
      logImpersonationAuditEvent("IMPERSONATION_TOKEN_REJECTED", req, {
        targetUserId: targetUser.id,
        reason: "self_impersonation_blocked",
      });
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "Cannot generate an impersonation token for yourself",
        {
          message: "Cannot generate an impersonation token for yourself",
        },
      );
    }

    if (!reason) {
      logImpersonationAuditEvent("IMPERSONATION_TOKEN_REJECTED", req, {
        targetUserId: targetUser.id,
        reason: "missing_support_reason",
      });
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "A support reason is required for impersonation",
        {
          message: "A support reason is required for impersonation",
        },
      );
    }

    const email =
      typeof targetUser.email === "string" && targetUser.email.trim()
        ? targetUser.email
        : `${targetUser.id}@impersonated.local`;
    const expiresAt = new Date(
      Date.now() + IMPERSONATION_TOKEN_TTL_MS,
    ).toISOString();
    const token = generateToken(
      {
        userId: targetUser.id,
        email,
        impersonation: {
          active: true,
          readOnly: true,
          actorUserId: actor.id,
          actorRole: actor.role,
          targetUserId: targetUser.id,
          reason,
          issuedAt: new Date().toISOString(),
        },
      },
      { expiresIn: IMPERSONATION_TOKEN_EXPIRES_IN },
    );

    logImpersonationAuditEvent("IMPERSONATION_TOKEN_ISSUED", req, {
      targetUserId: targetUser.id,
      supportReason: reason,
      expiresAt,
    });

    return res.status(201).json({
      message: "Read-only impersonation token generated",
      token,
      expiresAt,
      impersonation: {
        actorUserId: actor.id,
        actorRole: actor.role,
        targetUserId: targetUser.id,
        readOnly: true,
        reason,
      },
      guidance: READ_ONLY_IMPERSONATION_MESSAGE,
    });
  },
);

// POST /api/admin/users/bulk/unlock
router.post(
  "/users/bulk/unlock",
  requireAdmin,
  logAdminAction("BULK_UNLOCK_USERS"),
  async (req: Request, res: Response) => {
    try {
      const adminUser = (req as AuthRequest).user;
      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      const userIds = normalizeBulkIds(req.body?.userIds);
      if (userIds.length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "userIds must be a non-empty array of user IDs",
          {
            message: "userIds must be a non-empty array of user IDs",
          },
        );
      }

      if (userIds.length > MAX_BULK_IDS) {
        throw createError(
          ERROR_CODES.LIMIT_EXCEEDED,
          `Too many userIds supplied (max ${MAX_BULK_IDS})`,
          {
            message: `Too many userIds supplied (max ${MAX_BULK_IDS})`,
          },
        );
      }

      const results: BulkActionResult[] = [];

      for (const userId of userIds) {
        try {
          const user = users.find((u) => u.id === userId);
          if (!user) {
            results.push({
              userId,
              status: "failed",
              message: "User not found",
            });
            continue;
          }

          user.locked = false;
          results.push({ userId, status: "success" });
        } catch (error) {
          results.push({
            userId,
            status: "failed",
            message: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }

      const { succeededIds, failedIds } = splitBulkResults(
        results,
        (r) => r.userId,
      );

      recordBulkAudit(req, "BULK_UNLOCK_USERS", "user", succeededIds, {
        locked: false,
        requestedIds: userIds,
        failedIds,
      });

      const succeeded = results.filter((r) => r.status === "success").length;
      const failed = results.length - succeeded;

      return res.json({
        message: "Bulk unlock completed",
        summary: {
          total: results.length,
          succeeded,
          failed,
        },
        results,
      });
    } catch (error) {
      // Preserve validation errors (e.g. unknown/empty ids) instead of masking them as 500s.
      if ((error as { code?: string })?.code) throw error;
      console.error("Error bulk unlocking users:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);

// PUT /api/admin/users/:id
router.put(
  "/users/:id",
  requireAdmin,
  logAdminAction("UPDATE_USER"),
  (req: Request, res: Response) => {
    const user = users.find((u) => u.id === req.params.id);

    if (!user) {
      throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
        message: "User not found",
      });
    }

    Object.assign(user, req.body);

    res.json({ message: "User updated", user });
  },
);

// POST /api/admin/users/:id/unlock
router.post(
  "/users/:id/unlock",
  requireAdmin,
  logAdminAction("UNLOCK_USER"),
  (req: Request, res: Response) => {
    const user = users.find((u) => u.id === req.params.id);

    if (!user) {
      throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
        message: "User not found",
      });
    }

    user.locked = false;

    res.json({ message: "User account unlocked" });
  },
);

// POST /api/admin/users/:id/freeze
router.post(
  "/users/:id/freeze",
  requireAdmin,
  logAdminAction("FREEZE_USER"),
  async (req: Request, res: Response) => {
    try {
      const userId = req.params.id;
      const { reason } = req.body;
      const adminUser = (req as AuthRequest).user;

      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      // Validate reason
      if (!reason || typeof reason !== "string" || reason.trim().length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "A reason is required for freezing an account",
          {
            message: "A reason is required for freezing an account",
          },
        );
      }

      const userModel = new UserModel();

      // Check if user exists
      const user = await userModel.findById(userId);
      if (!user) {
        throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
          message: "User not found",
        });
      }

      // Check if already frozen
      if (user.status === "frozen") {
        throw createError(
          ERROR_CODES.CONFLICT,
          "User account is already frozen",
          {
            message: "User account is already frozen",
          },
        );
      }

      // Freeze the user
      const updatedUser = await userModel.updateStatus(
        userId,
        "frozen",
        adminUser.id,
        reason.trim(),
        req.ip,
        req.get("user-agent"),
      );

      if (!updatedUser) {
        throw createError(
          ERROR_CODES.INTERNAL_ERROR,
          "Failed to freeze user account",
          {
            message: "Failed to freeze user account",
          },
        );
      }

      console.log(`[ADMIN] User account frozen: ${userId}`, {
        adminId: adminUser.id,
        targetUserId: userId,
        reason: reason.trim(),
        timestamp: new Date().toISOString(),
      });

      res.json({
        message: "User account frozen successfully",
        user: {
          id: updatedUser.id,
          status: updatedUser.status,
        },
      });
    } catch (error) {
      console.error("Error freezing user account:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);

// POST /api/admin/users/:id/unfreeze
router.post(
  "/users/:id/unfreeze",
  requireAdmin,
  logAdminAction("UNFREEZE_USER"),
  async (req: Request, res: Response) => {
    try {
      const userId = req.params.id;
      const { reason } = req.body;
      const adminUser = (req as AuthRequest).user;

      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      // Validate reason
      if (!reason || typeof reason !== "string" || reason.trim().length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "A reason is required for unfreezing an account",
          {
            message: "A reason is required for unfreezing an account",
          },
        );
      }

      const userModel = new UserModel();

      // Check if user exists
      const user = await userModel.findById(userId);
      if (!user) {
        throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
          message: "User not found",
        });
      }

      // Check if not frozen
      if (user.status !== "frozen") {
        throw createError(ERROR_CODES.CONFLICT, "User account is not frozen", {
          message: "User account is not frozen",
        });
      }

      // Unfreeze the user
      const updatedUser = await userModel.updateStatus(
        userId,
        "active",
        adminUser.id,
        reason.trim(),
        req.ip,
        req.get("user-agent"),
      );

      if (!updatedUser) {
        throw createError(
          ERROR_CODES.INTERNAL_ERROR,
          "Failed to unfreeze user account",
          {
            message: "Failed to unfreeze user account",
          },
        );
      }

      console.log(`[ADMIN] User account unfrozen: ${userId}`, {
        adminId: adminUser.id,
        targetUserId: userId,
        reason: reason.trim(),
        timestamp: new Date().toISOString(),
      });

      res.json({
        message: "User account unfrozen successfully",
        user: {
          id: updatedUser.id,
          status: updatedUser.status,
        },
      });
    } catch (error) {
      console.error("Error unfreezing user account:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);

// GET /api/admin/users/:id/status-history
router.get(
  "/users/:id/status-history",
  requireAdmin,
  logAdminAction("GET_USER_STATUS_HISTORY"),
  async (req: Request, res: Response) => {
    try {
      const userId = req.params.id;
      const userModel = new UserModel();

      // Check if user exists
      const user = await userModel.findById(userId);
      if (!user) {
        throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
          message: "User not found",
        });
      }

      const auditHistory = await userModel.getAuditHistory(userId);

      res.json({
        userId: user.id,
        currentStatus: user.status,
        history: auditHistory,
      });
    } catch (error) {
      console.error("Error fetching user status history:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);

/**
 * =========================
 * DASHBOARD CONFIGURATION
 * =========================
 */

// GET /api/admin/users/:id/dashboard-config
router.get(
  "/users/:id/dashboard-config",
  requireAdmin,
  logAdminAction("GET_DASHBOARD_CONFIG"),
  (req: Request, res: Response) => {
    const user = users.find((u) => u.id === req.params.id);

    if (!user) {
      throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
        message: "User not found",
      });
    }

    const config = user.dashboard_config || {
      layout: "grid",
      widgets: [],
    };

    res.json({
      userId: user.id,
      config,
    });
  },
);

// PUT /api/admin/users/:id/dashboard-config
router.put(
  "/users/:id/dashboard-config",
  requireAdmin,
  logAdminAction("UPDATE_DASHBOARD_CONFIG"),
  (req: Request, res: Response) => {
    const user = users.find((u) => u.id === req.params.id);

    if (!user) {
      throw createError(ERROR_CODES.NOT_FOUND, "User not found", {
        message: "User not found",
      });
    }

    const { config } = req.body;

    // Validate the dashboard config against the JSON schema
    if (!validateDashboardConfig(config)) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "Invalid dashboard configuration",
        {
          message: "Invalid dashboard configuration",
          errors: DASHBOARD_CONFIG_VALIDATION_ERRORS,
        },
      );
    }

    // Save the configuration
    user.dashboard_config = config;

    res.json({
      message: "Dashboard configuration saved",
      userId: user.id,
      config: user.dashboard_config,
    });
  },
);

// GET /api/admin/dashboard/config — get current user's dashboard config
router.get(
  "/dashboard/config",
  requireAdmin,
  logAdminAction("GET_MY_DASHBOARD_CONFIG"),
  (req: Request, res: Response) => {
    const authReq = req as AuthRequest;
    const userId = authReq.user?.id;
    const user = users.find((u) => u.id === userId);
    const config: DashboardConfig = user?.dashboard_config || {
      layout: "grid",
      widgets: [],
    };
    res.json({ userId, config });
  },
);

// PUT /api/admin/dashboard/config — replace entire dashboard config
router.put(
  "/dashboard/config",
  requireAdmin,
  logAdminAction("PUT_MY_DASHBOARD_CONFIG"),
  (req: Request, res: Response) => {
    const authReq = req as AuthRequest;
    const userId = authReq.user?.id;
    const { config } = req.body;

    if (!validateDashboardConfig(config)) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "Invalid dashboard configuration",
        {
          message: "Invalid dashboard configuration",
          errors: DASHBOARD_CONFIG_VALIDATION_ERRORS,
        },
      );
    }

    let user = users.find((u) => u.id === userId);
    if (!user) {
      user = { id: userId as string, role: authReq.user?.role || "admin" };
      users.push(user);
    }
    user.dashboard_config = config;

    res.json({ message: "Dashboard configuration saved", userId, config });
  },
);

// PATCH /api/admin/dashboard/widgets/reorder — reorder widgets
router.patch(
  "/dashboard/widgets/reorder",
  requireAdmin,
  logAdminAction("REORDER_DASHBOARD_WIDGETS"),
  (req: Request, res: Response) => {
    const authReq = req as AuthRequest;
    const userId = authReq.user?.id;
    const { fromIndex, toIndex } = req.body;

    if (typeof fromIndex !== "number" || typeof toIndex !== "number") {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "fromIndex and toIndex must be numbers",
        { message: "fromIndex and toIndex must be numbers" },
      );
    }

    let user = users.find((u) => u.id === userId);
    if (!user) {
      user = { id: userId as string, role: authReq.user?.role || "admin" };
      users.push(user);
    }

    const current: DashboardConfig = user.dashboard_config || {
      layout: "grid",
      widgets: [],
    };

    user.dashboard_config = reorderWidgets(current, fromIndex, toIndex);
    res.json({
      message: "Widgets reordered",
      userId,
      config: user.dashboard_config,
    });
  },
);

// PATCH /api/admin/dashboard/widgets/:widgetId/visibility — toggle visibility
router.patch(
  "/dashboard/widgets/:widgetId/visibility",
  requireAdmin,
  logAdminAction("TOGGLE_WIDGET_VISIBILITY"),
  (req: Request, res: Response) => {
    const authReq = req as AuthRequest;
    const userId = authReq.user?.id;
    const { widgetId } = req.params;

    let user = users.find((u) => u.id === userId);
    if (!user) {
      user = { id: userId as string, role: authReq.user?.role || "admin" };
      users.push(user);
    }

    const current: DashboardConfig = user.dashboard_config || {
      layout: "grid",
      widgets: [],
    };

    user.dashboard_config = toggleWidgetVisibility(current, widgetId);
    res.json({
      message: "Widget visibility toggled",
      userId,
      config: user.dashboard_config,
    });
  },
);

// PATCH /api/admin/dashboard/widgets/:widgetId/refresh-rate — set refresh rate
router.patch(
  "/dashboard/widgets/:widgetId/refresh-rate",
  requireAdmin,
  logAdminAction("SET_WIDGET_REFRESH_RATE"),
  (req: Request, res: Response) => {
    const authReq = req as AuthRequest;
    const userId = authReq.user?.id;
    const { widgetId } = req.params;
    const { refreshRateSecs } = req.body;

    if (typeof refreshRateSecs !== "number") {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "refreshRateSecs must be a number",
        { message: "refreshRateSecs must be a number" },
      );
    }

    let user = users.find((u) => u.id === userId);
    if (!user) {
      user = { id: userId as string, role: authReq.user?.role || "admin" };
      users.push(user);
    }

    const current: DashboardConfig = user.dashboard_config || {
      layout: "grid",
      widgets: [],
    };

    user.dashboard_config = setWidgetRefreshRate(
      current,
      widgetId,
      refreshRateSecs,
    );
    res.json({
      message: "Widget refresh rate updated",
      userId,
      config: user.dashboard_config,
    });
  },
);

// provider balance route
router.get("/providers/balances", requireAdmin, async (req, res) => {
  const mobileMoneyService = new MobileMoneyService();
  const balances = await mobileMoneyService.getAllProviderBalances();

  return res.json({
    success: true,
    data: balances,
  });
});

/**
 * =========================
 * TRANSACTIONS
 * =========================
 */

// GET /api/admin/transactions
router.get(
  "/transactions",
  requireAdmin,
  logAdminAction("LIST_TRANSACTIONS"),
  async (req: Request, res: Response) => {
    try {
      const page = Number(req.query.page) || 1;
      const limit = Number(req.query.limit) || 10;
      const reference = req.query.reference as string | undefined;

      const offset = (page - 1) * limit;

      const filters: any = {};
      if (reference) {
        filters.referenceNumber = reference;
      }

      const transactions = await transactionModel.list(
        limit,
        offset,
        undefined,
        undefined,
        filters,
      );
      const total = await transactionModel.count(undefined, undefined, filters);

      res.json({
        data: transactions,
        pagination: {
          total,
          page,
          limit,
          totalPages: Math.ceil(total / limit),
        },
      });
    } catch (err) {
      console.error("Error listing transactions for admin:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to list transactions",
        {
          error: "Failed to list transactions",
        },
      );
    }
  },
);

// PUT /api/admin/transactions/:id
router.put(
  "/transactions/:id",
  requireAdmin,
  rateLimitListQueries,
  logAdminAction("UPDATE_TRANSACTION"),
  async (req: Request, res: Response) => {
    try {
      const tx = await transactionModel.findById(req.params.id);

      if (!tx) {
        throw createError(ERROR_CODES.NOT_FOUND, "Transaction not found", {
          message: "Transaction not found",
        });
      }

      // Basic update logic - in a real app this would be more specific
      if (req.body.admin_notes) {
        await transactionModel.updateAdminNotes(
          req.params.id,
          req.body.admin_notes,
        );
      }

      if (req.body.status) {
        await transactionModel.updateStatus(req.params.id, req.body.status);
      }

      const updatedTx = await transactionModel.findById(req.params.id);
      res.json({ message: "Transaction updated", transaction: updatedTx });
    } catch (err) {
      console.error("Error updating transaction:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to update transaction",
      );
    }
  },
);

// PATCH /api/admin/transactions/:id/notes
router.patch(
  "/transactions/:id/notes",
  requireAdmin,
  logAdminAction("UPDATE_TRANSACTION_ADMIN_NOTES"),
  updateAdminNotesHandler,
);

// POST /api/admin/transactions/:id/refund
router.post(
  "/transactions/:id/refund",
  requireAdmin,
  logAdminAction("REFUND_TRANSACTION"),
  refundTransactionHandler,
);

// PATCH /api/admin/transactions/bulk/notes
router.patch(
  "/transactions/bulk/notes",
  requireAdmin,
  logAdminAction("BULK_UPDATE_TRANSACTION_ADMIN_NOTES"),
  async (req: Request, res: Response) => {
    try {
      const adminUser = (req as AuthRequest).user;
      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      const { admin_notes: adminNotes } = req.body;
      if (typeof adminNotes !== "string") {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "admin_notes must be a string",
          {
            message: "admin_notes must be a string",
          },
        );
      }

      const transactionIds = normalizeBulkIds(req.body?.transactionIds);
      if (transactionIds.length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "transactionIds must be a non-empty array of transaction IDs",
          {
            message:
              "transactionIds must be a non-empty array of transaction IDs",
          },
        );
      }

      if (transactionIds.length > MAX_BULK_IDS) {
        throw createError(
          ERROR_CODES.LIMIT_EXCEEDED,
          `Too many transactionIds supplied (max ${MAX_BULK_IDS})`,
          {
            message: `Too many transactionIds supplied (max ${MAX_BULK_IDS})`,
          },
        );
      }

      const results: BulkTransactionActionResult[] = [];

      for (const transactionId of transactionIds) {
        try {
          const tx = await transactionModel.findById(transactionId);
          if (!tx) {
            results.push({
              transactionId,
              status: "failed",
              message: "Transaction not found",
            });
            continue;
          }

          await transactionModel.updateAdminNotes(transactionId, adminNotes);
          results.push({ transactionId, status: "success" });
        } catch (error) {
          results.push({
            transactionId,
            status: "failed",
            message: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }

      const { succeededIds, failedIds } = splitBulkResults(
        results,
        (r) => r.transactionId,
      );

      recordBulkAudit(
        req,
        "BULK_UPDATE_TRANSACTION_ADMIN_NOTES",
        "transaction",
        succeededIds,
        {
          adminNotes: adminNotes,
          requestedIds: transactionIds,
          failedIds,
        },
      );

      const succeeded = results.filter((r) => r.status === "success").length;
      const failed = results.length - succeeded;

      return res.json({
        message: "Bulk admin notes update completed",
        summary: { total: results.length, succeeded, failed },
        results,
      });
    } catch (error) {
      // Preserve validation errors (e.g. unknown/empty ids) instead of masking them as 500s.
      if ((error as { code?: string })?.code) throw error;
      console.error("Error bulk updating transaction admin notes:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);

// PATCH /api/admin/transactions/bulk/status
router.patch(
  "/transactions/bulk/status",
  requireAdmin,
  logAdminAction("BULK_UPDATE_TRANSACTION_STATUS"),
  async (req: Request, res: Response) => {
    try {
      const adminUser = (req as AuthRequest).user;
      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      const { status } = req.body;
      const allowed = Object.values(TransactionStatus) as string[];
      if (typeof status !== "string" || !allowed.includes(status)) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          `status must be one of: ${allowed.join(", ")}`,
          {
            message: `status must be one of: ${allowed.join(", ")}`,
          },
        );
      }

      const transactionIds = normalizeBulkIds(req.body?.transactionIds);
      if (transactionIds.length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "transactionIds must be a non-empty array of transaction IDs",
          {
            message:
              "transactionIds must be a non-empty array of transaction IDs",
          },
        );
      }

      if (transactionIds.length > MAX_BULK_IDS) {
        throw createError(
          ERROR_CODES.LIMIT_EXCEEDED,
          `Too many transactionIds supplied (max ${MAX_BULK_IDS})`,
          {
            message: `Too many transactionIds supplied (max ${MAX_BULK_IDS})`,
          },
        );
      }

      const results: BulkTransactionActionResult[] = [];

      for (const transactionId of transactionIds) {
        try {
          const tx = await transactionModel.findById(transactionId);
          if (!tx) {
            results.push({
              transactionId,
              status: "failed",
              message: "Transaction not found",
            });
            continue;
          }

          await transactionModel.updateStatus(
            transactionId,
            status as TransactionStatus,
          );
          results.push({ transactionId, status: "success" });
        } catch (error) {
          results.push({
            transactionId,
            status: "failed",
            message: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }

      const { succeededIds, failedIds } = splitBulkResults(
        results,
        (r) => r.transactionId,
      );

      recordBulkAudit(
        req,
        "BULK_UPDATE_TRANSACTION_STATUS",
        "transaction",
        succeededIds,
        {
          status,
          requestedIds: transactionIds,
          failedIds,
        },
      );

      const succeeded = results.filter((r) => r.status === "success").length;
      const failed = results.length - succeeded;

      return res.json({
        message: "Bulk status update completed",
        summary: { total: results.length, succeeded, failed },
        results,
      });
    } catch (error) {
      // Preserve validation errors (e.g. unknown/empty ids) instead of masking them as 500s.
      if ((error as { code?: string })?.code) throw error;
      console.error("Error bulk updating transaction status:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);
// POST /api/admin/transactions/bulk/refund
router.post(
  "/transactions/bulk/refund",
  requireAdmin,
  logAdminAction("BULK_REFUND_TRANSACTIONS"),
  async (req: Request, res: Response) => {
    try {
      const adminUser = (req as AuthRequest).user;
      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      const transactionIds = normalizeBulkIds(req.body?.transactionIds);
      if (transactionIds.length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "transactionIds must be a non-empty array of transaction IDs",
          {
            message:
              "transactionIds must be a non-empty array of transaction IDs",
          },
        );
      }

      if (transactionIds.length > MAX_BULK_IDS) {
        throw createError(
          ERROR_CODES.LIMIT_EXCEEDED,
          `Too many transactionIds supplied (max ${MAX_BULK_IDS})`,
          {
            message: `Too many transactionIds supplied (max ${MAX_BULK_IDS})`,
          },
        );
      }

      const { calculateFee } = await import("../utils/fees.js");
      const results: BulkTransactionActionResult[] = [];

      for (const transactionId of transactionIds) {
        try {
          const transaction = await transactionModel.findById(transactionId);
          if (!transaction) {
            results.push({
              transactionId,
              status: "failed",
              message: "Transaction not found",
            });
            continue;
          }

          if (transaction.type !== "withdraw") {
            results.push({
              transactionId,
              status: "failed",
              message: "Only withdrawal transactions can be refunded",
            });
            continue;
          }

          if (transaction.status !== TransactionStatus.Failed) {
            results.push({
              transactionId,
              status: "failed",
              message: `Cannot refund transaction with status '${transaction.status}'. Only failed transactions are eligible.`,
            });
            continue;
          }

          const amount = parseFloat(transaction.amount);
          const { fee } = await calculateFee(amount);
          const refundAmount = parseFloat((amount - fee).toFixed(2));
          if (refundAmount <= 0) {
            results.push({
              transactionId,
              status: "failed",
              message: "Refund amount after fees is zero or negative",
            });
            continue;
          }

          await transactionModel.updateStatus(
            transactionId,
            TransactionStatus.Completed,
          );

          results.push({ transactionId, status: "success" });
        } catch (error) {
          results.push({
            transactionId,
            status: "failed",
            message: error instanceof Error ? error.message : "Unknown error",
          });
        }
      }

      const { succeededIds, failedIds } = splitBulkResults(
        results,
        (r) => r.transactionId,
      );

      recordBulkAudit(
        req,
        "BULK_REFUND_TRANSACTIONS",
        "transaction",
        succeededIds,
        {
          requestedIds: transactionIds,
          failedIds,
        },
      );

      const succeeded = results.filter((r) => r.status === "success").length;
      const failed = results.length - succeeded;

      return res.json({
        message: "Bulk refund completed",
        summary: { total: results.length, succeeded, failed },
        results,
      });
    } catch (error) {
      // Preserve validation errors (e.g. unknown/empty ids) instead of masking them as 500s.
      if ((error as { code?: string })?.code) throw error;
      console.error("Error bulk refunding transactions:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Internal server error");
    }
  },
);

/**
 * =========================
 * QUEUES & DLQ
 * =========================
 */

// GET /api/admin/queues/dlq
// Query params: queueName, failureReason, from, to, limit, offset
router.get(
  "/queues/dlq",
  requireAdmin,
  logAdminAction("VIEW_DLQ"),
  async (req: Request, res: Response) => {
    const { queueName, failureReason, from, to } = req.query as Record<
      string,
      string | undefined
    >;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
    const offset = parseInt(req.query.offset as string) || 0;

    const { items, total } = await queryDLQ({
      queueName,
      failureReason,
      from,
      to,
      limit,
      offset,
    });
    res.json({ success: true, total, limit, offset, items });
  },
);

// POST /api/admin/dlq/:jobId/replay
router.post(
  "/dlq/:jobId/replay",
  requireAdmin,
  logAdminAction("REPLAY_DLQ_ENTRY"),
  async (req: Request, res: Response) => {
    const { jobId } = req.params;
    const admin = (req as AuthRequest).user;
    if (!admin) {
      throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required");
    }

    const entry = await replayDLQEntry(jobId, admin.id);
    res.json({ success: true, entry });
  },
);

/**
 * =========================
 * LIQUIDITY MANAGEMENT
 * =========================
 */

// GET /api/admin/liquidity/transfers
router.get(
  "/liquidity/transfers",
  requireAdmin,
  logAdminAction("LIST_LIQUIDITY_TRANSFERS"),
  async (req: Request, res: Response) => {
    try {
      const limit = Number(req.query.limit) || 50;
      const offset = Number(req.query.offset) || 0;
      const transfers = await getLiquidityTransfers(limit, offset);
      res.json({ transfers });
    } catch (err) {
      console.error("[liquidity] Failed to list transfers:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to retrieve liquidity transfers",
      );
    }
  },
);

// POST /api/admin/liquidity/transfers
router.post(
  "/liquidity/transfers",
  requireAdmin,
  logAdminAction("MANUAL_LIQUIDITY_TRANSFER"),
  async (req: Request, res: Response) => {
    try {
      const { fromProvider, toProvider, amount, note } = req.body;
      const admin = (req as AuthRequest).user;

      if (!admin) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }
      if (!fromProvider || !toProvider || !amount) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "fromProvider, toProvider, and amount are required",
          {
            message: "fromProvider, toProvider, and amount are required",
          },
        );
      }
      if (fromProvider === toProvider) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "fromProvider and toProvider must be different",
          {
            message: "fromProvider and toProvider must be different",
          },
        );
      }
      if (typeof amount !== "number" || amount <= 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "amount must be a positive number",
          {
            message: "amount must be a positive number",
          },
        );
      }

      const result = await triggerManualTransfer(
        fromProvider,
        toProvider,
        amount,
        admin.id,
        note,
      );
      res.status(201).json({ message: "Transfer initiated", ...result });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Transfer failed";
      console.error("[liquidity] Manual transfer error:", err);
      throw createError(ERROR_CODES.INTERNAL_ERROR, msg);
    }
  },
);

/**
 * =========================
 * CSV RECONCILIATION
 * =========================
 */

// POST /api/admin/reconcile
router.post(
  "/reconcile",
  requireAdmin,
  logAdminAction("CSV_RECONCILIATION"),
  csvUpload.single("csv") as any,
  async (req: Request, res: Response) => {
    try {
      if (!req.file) {
        throw createError(ERROR_CODES.INVALID_INPUT, "No file uploaded", {
          error: "No file uploaded",
          message: "Please upload a CSV file with field name 'csv'",
        });
      }

      // Parse optional date range from query params
      const dateRange = {
        start: req.query.start_date as string | undefined,
        end: req.query.end_date as string | undefined,
      };

      // Parse CSV
      const providerRows = await parseCSV(req.file.buffer);

      if (providerRows.length === 0) {
        throw createError(ERROR_CODES.INVALID_INPUT, "Empty CSV", {
          error: "Empty CSV",
          message: "The uploaded CSV file contains no data rows",
        });
      }

      // Perform reconciliation
      const result = await reconcileTransactions(providerRows, dateRange);

      // Log reconciliation summary
      console.log("[CSV RECONCILIATION]", {
        adminId: (req as AuthRequest).user?.id,
        filename: req.file.originalname,
        summary: result.summary,
        timestamp: new Date().toISOString(),
      });

      res.json({
        message: "Reconciliation completed successfully",
        result,
      });
    } catch (error) {
      console.error("[CSV RECONCILIATION ERROR]", error);

      if (error instanceof Error) {
        throw createError(ERROR_CODES.INTERNAL_ERROR, "Reconciliation failed", {
          error: "Reconciliation failed",
          message: error.message,
        });
      }

      throw createError(ERROR_CODES.INTERNAL_ERROR, "Reconciliation failed", {
        error: "Reconciliation failed",
        message: "An unexpected error occurred during reconciliation",
      });
    }
  },
);

/**
 * =========================
 * PROVIDER RECONCILIATION
 * =========================
 */

const providerReconciliationService = new ProviderReconciliationService();

// GET /api/admin/reconciliation/runs - List reconciliation runs
router.get(
  "/reconciliation/runs",
  requireAdmin,
  logAdminAction("LIST_RECONCILIATION_RUNS"),
  async (req: Request, res: Response) => {
    try {
      const page = Number(req.query.page) || 1;
      const limit = Number(req.query.limit) || 20;
      const provider = req.query.provider as string | undefined;

      const offset = (page - 1) * limit;
      const runs = await providerReconciliationService.getReconciliationHistory(
        provider,
        limit,
      );

      // Apply pagination
      const paginatedRuns = runs.slice(offset, offset + limit);
      const total = runs.length;

      res.json({
        data: paginatedRuns,
        pagination: {
          total,
          page,
          limit,
          totalPages: Math.ceil(total / limit),
        },
      });
    } catch (error) {
      console.error("Error fetching reconciliation runs:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch reconciliation runs",
      );
    }
  },
);

// GET /api/admin/reconciliation/alerts - List reconciliation alerts
router.get(
  "/reconciliation/alerts",
  requireAdmin,
  logAdminAction("LIST_RECONCILIATION_ALERTS"),
  async (req: Request, res: Response) => {
    try {
      const page = Number(req.query.page) || 1;
      const limit = Number(req.query.limit) || 50;
      const status = req.query.status as string | undefined;
      const severity = req.query.severity as string | undefined;

      const alerts = await providerReconciliationService.getPendingAlerts(1000); // Get more to filter

      // Apply filters
      let filteredAlerts = alerts;
      if (status) {
        filteredAlerts = filteredAlerts.filter(
          (alert) => alert.status === status,
        );
      }
      if (severity) {
        filteredAlerts = filteredAlerts.filter(
          (alert) => alert.severity === severity,
        );
      }

      // Apply pagination
      const offset = (page - 1) * limit;
      const paginatedAlerts = filteredAlerts.slice(offset, offset + limit);

      res.json({
        data: paginatedAlerts,
        pagination: {
          total: filteredAlerts.length,
          page,
          limit,
          totalPages: Math.ceil(filteredAlerts.length / limit),
        },
      });
    } catch (error) {
      console.error("Error fetching reconciliation alerts:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch reconciliation alerts",
      );
    }
  },
);
// PATCH /api/admin/reconciliation/alerts/:id - Review reconciliation alert
router.patch(
  "/reconciliation/alerts/:id",
  requireAdmin,
  logAdminAction("REVIEW_RECONCILIATION_ALERT"),
  async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const { status, review_notes } = req.body;
      const adminUser = (req as AuthRequest).user;

      if (!adminUser) {
        throw createError(ERROR_CODES.UNAUTHORIZED, "Authentication required", {
          message: "Authentication required",
        });
      }

      const allowedStatuses = ["reviewed", "dismissed", "resolved"];
      if (!allowedStatuses.includes(status)) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          `Status must be one of: ${allowedStatuses.join(", ")}`,
          {
            message: `Status must be one of: ${allowedStatuses.join(", ")}`,
          },
        );
      }

      if (
        !review_notes ||
        typeof review_notes !== "string" ||
        review_notes.trim().length === 0
      ) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "Review notes are required",
          {
            message: "Review notes are required",
          },
        );
      }

      await providerReconciliationService.reviewAlert(
        id,
        status,
        review_notes.trim(),
        adminUser.id,
      );

      res.json({ message: "Alert reviewed successfully" });
    } catch (error) {
      console.error("Error reviewing reconciliation alert:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Failed to review alert");
    }
  },
);

// POST /api/admin/reconciliation/manual - Run manual reconciliation
router.post(
  "/reconciliation/manual",
  requireAdmin,
  logAdminAction("RUN_MANUAL_RECONCILIATION"),
  async (req: Request, res: Response) => {
    try {
      const { provider, report_date } = req.body;

      if (!provider || !report_date) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "Provider and report_date are required",
          {
            message: "Provider and report_date are required",
          },
        );
      }

      const reportDate = new Date(report_date);
      if (isNaN(reportDate.getTime())) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "Invalid report_date format. Use ISO date string.",
          {
            message: "Invalid report_date format. Use ISO date string.",
          },
        );
      }

      const { runManualProviderReconciliation } =
        await import("../jobs/providerReconciliationJob.js");
      const result = await runManualProviderReconciliation(
        provider,
        reportDate,
      );

      res.json({
        message: "Manual reconciliation completed",
        result,
      });
    } catch (error) {
      console.error("Error running manual reconciliation:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Manual reconciliation failed",
        {
          message: "Manual reconciliation failed",
          error: error instanceof Error ? error.message : "Unknown error",
        },
      );
    }
  },
);

// GET /api/admin/reconciliation/configs - List provider report configs
router.get(
  "/reconciliation/configs",
  requireAdmin,
  logAdminAction("LIST_RECONCILIATION_CONFIGS"),
  async (req: Request, res: Response) => {
    try {
      const configs = await providerReconciliationService.getProviderConfigs();
      res.json({ data: configs });
    } catch (error) {
      console.error("Error fetching reconciliation configs:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch reconciliation configs",
      );
    }
  },
);

/**
 * =========================
 * HEALTH & MONITORING
 * =========================
 */

// GET /api/admin/providers/health
router.get(
  "/providers/health",
  requireAdmin,
  logAdminAction("GET_PROVIDER_HEALTH"),
  async (req: Request, res: Response) => {
    try {
      const timestamp = new Date().toISOString();
      const mobileMoneyService = new MobileMoneyService();

      // Get failover stats
      let providers = {};
      try {
        providers = mobileMoneyService.getFailoverStats();
      } catch (err) {
        console.error("Error fetching failover stats:", err);
      }

      // Get queue stats
      let queue = { status: "unknown", stats: {} };
      try {
        const queueStats = await getQueueStats();
        queue = {
          status: queueStats.failed > 100 ? "degraded" : "healthy",
          stats: queueStats,
        };
      } catch (err) {
        console.error("Error fetching queue stats:", err);
      }

      // Get Redis status
      const redis = { status: "unknown" };
      try {
        if (redisClient.isOpen) {
          await redisClient.ping();
          redis.status = "ok";
        } else {
          redis.status = "closed";
        }
      } catch (err) {
        console.error("Error checking Redis status:", err);
        redis.status = "down";
      }

      // Get database replica health
      let database: {
        primary: string;
        replicas: { url: string; healthy: boolean }[];
      } = {
        primary: "unknown",
        replicas: [],
      };
      try {
        const replicaHealth = await checkReplicaHealth();
        database = {
          primary: "ok", // Primary is assumed ok if we can query replicas
          replicas: replicaHealth,
        };
      } catch (err) {
        console.error("Error checking database health:", err);
      }

      res.json({
        status: "healthy",
        timestamp,
        providers,
        queue,
        redis,
        database,
      });
    } catch (err) {
      console.error("Health check error:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to retrieve health data",
        {
          status: "error",
          message: "Failed to retrieve health data",
          timestamp: new Date().toISOString(),
        },
      );
    }
  },
);

// GET /api/admin/database/replication — cross-region replication status
router.get(
  "/database/replication",
  requireAdmin,
  logAdminAction("GET_DATABASE_REPLICATION"),
  async (_req: Request, res: Response) => {
    try {
      const stats = await getPoolStats();
      res.json({ success: true, ...stats });
    } catch (err) {
      console.error("Error fetching replication status:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch replication status",
        {
          message: err instanceof Error ? err.message : "Unknown error",
        },
      );
    }
  },
);

/**
 * =========================
 * FINANCIAL DASHBOARD
 * =========================
 */

// GET /api/admin/financial/pnl - last 30 days of daily PnL snapshots
router.get(
  "/financial/pnl",
  requireAdmin,
  async (_req: Request, res: Response) => {
    try {
      const { queryRead } = await import("../config/database.js");
      const result = await queryRead<{
        report_date: string;
        user_fees: string;
        provider_fees: string;
        pnl: string;
      }>(
        `SELECT report_date, user_fees, provider_fees, pnl
         FROM daily_pnl_snapshots
         WHERE report_date >= CURRENT_DATE - INTERVAL '29 days'
         ORDER BY report_date ASC`,
        [],
      );

      const rows = result.rows.map((r) => ({
        date: r.report_date,
        feesCollected: parseFloat(r.user_fees),
        providerCosts: parseFloat(r.provider_fees),
        netProfit: parseFloat(r.pnl),
      }));

      const totals = rows.reduce(
        (acc, r) => ({
          feesCollected: acc.feesCollected + r.feesCollected,
          providerCosts: acc.providerCosts + r.providerCosts,
          netProfit: acc.netProfit + r.netProfit,
        }),
        { feesCollected: 0, providerCosts: 0, netProfit: 0 },
      );

      res.json({ rows, totals });
    } catch (err) {
      console.error("[financial/pnl]", err);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Failed to fetch PnL data");
    }
  },
);

router.get(
  "/financial/dashboard/manifest.json",
  requireAdmin,
  (_req: Request, res: Response) => {
    res.json({
      name: "ProxyPay Financial Dashboard",
      short_name: "ProxyPay",
      description:
        "Mobile-friendly financial dashboard with offline cached transaction insights.",
      start_url: "/api/admin/financial/dashboard",
      display: "standalone",
      background_color: "#020817",
      theme_color: "#0f172a",
      orientation: "portrait-primary",
      scope: "/api/admin/financial/dashboard/",
      icons: [
        {
          src: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 128 128'%3E%3Crect width='128' height='128' rx='24' fill='%230f172a'/%3E%3Cpath d='M26 90h76V38H68l-10 10H26v42zm18-28h40v8H44v-8zm0 18h26v8H44v-8z' fill='%2360a5fa'/%3E%3C/svg%3E",
          sizes: "128x128",
          type: "image/svg+xml",
          purpose: "any maskable",
        },
      ],
    });
  },
);

router.get(
  "/financial/dashboard/sw.js",
  requireAdmin,
  (_req: Request, res: Response) => {
    res.type("application/javascript");
    res.send(`const CACHE_NAME = 'proxypay-financial-dashboard-v1';
const APP_SHELL = [
  '/api/admin/financial/dashboard',
  '/api/admin/financial/dashboard/manifest.json',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys
        .filter((key) => key !== CACHE_NAME)
        .map((key) => caches.delete(key)),
    )).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);
  const isDashboard = url.pathname === '/api/admin/financial/dashboard';
  const isPnl = url.pathname === '/api/admin/financial/pnl';
  const isTransactions = url.pathname === '/api/admin/transactions';

  if (isDashboard || isPnl || isTransactions) {
    event.respondWith(
      caches.open(CACHE_NAME).then(async (cache) => {
        try {
          const networkResponse = await fetch(event.request);
          if (networkResponse.ok) {
            cache.put(event.request, networkResponse.clone());
          }
          return networkResponse;
        } catch (error) {
          const cachedResponse = await cache.match(event.request);
          if (cachedResponse) return cachedResponse;
          return cache.match('/api/admin/financial/dashboard');
        }
      }),
    );
    return;
  }

  if (url.origin === self.location.origin) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request)),
    );
  }
});`);
  },
);

// GET /api/admin/financial/dashboard - self-contained HTML dashboard
router.get(
  "/financial/dashboard",
  requireAdmin,
  (_req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#0f172a">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>Financial Dashboard</title>
<link rel="manifest" href="/api/admin/financial/dashboard/manifest.json">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#020817;color:#e2e8f0;padding:24px}
  .app-shell{max-width:1100px;margin:0 auto;padding-bottom:64px}
  .topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:20px;flex-wrap:wrap}
  h1{font-size:clamp(1.3rem,2vw,1.8rem);font-weight:700;color:#f8fafc}
  .install-button{background:#2563eb;color:#fff;border:none;padding:10px 16px;border-radius:8px;font-weight:600;cursor:pointer;display:none}
  .install-button.visible{display:inline-flex}
  .cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-bottom:28px}
  .card{background:#111827;border-radius:12px;padding:18px;border:1px solid rgba(148,163,184,.15);box-shadow:0 10px 30px rgba(15,23,42,.18)}
  .card .label{font-size:.72rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
  .card .value{font-size:clamp(1.2rem,2vw,1.8rem);font-weight:700}
  .green{color:#34d399}.red{color:#f87171}.blue{color:#60a5fa}
  .chart-box{background:#111827;border-radius:12px;padding:20px;border:1px solid rgba(148,163,184,.15)}
  .chart-box h2{font-size:.9rem;color:#94a3b8;margin-bottom:16px;font-weight:600}
  #status{font-size:.75rem;color:#64748b;margin-top:14px;text-align:right}
  .error{color:#f87171;padding:20px;background:#111827;border-radius:10px;border:1px solid rgba(248,113,113,.28)}
  .copy-icon{cursor:pointer;color:#60a5fa;opacity:0.7;transition:opacity .2s}
  .copy-icon:hover{opacity:1}
  .toast{position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#34d399;color:#0f172a;padding:10px 20px;border-radius:6px;font-weight:700;font-size:.85rem;z-index:1000;opacity:0;transition:opacity .3s}
  .toast.show{opacity:1}
  input,button{font:inherit}
  @media (max-width:768px){
    body{padding:16px 12px 40px}
    .cards{grid-template-columns:1fr}
    .topbar{align-items:flex-start}
    .chart-box{padding:14px}
    .card{padding:16px}
  }
 </style>
</head>
<body>
<div class="app-shell">
  <div class="topbar">
    <h1>Financial Health — Last 30 Days</h1>
    <button id="installBtn" class="install-button" aria-label="Install dashboard">Install App</button>
  </div>
  <div class="cards">
    <div class="card"><div class="label">Fees Collected</div><div class="value green" id="totalFees">—</div></div>
    <div class="card"><div class="label">Provider Costs</div><div class="value red" id="totalCosts">—</div></div>
    <div class="card"><div class="label">Net Profit</div><div class="value blue" id="totalProfit">—</div></div>
  </div>
  <div class="chart-box">
    <h2>Daily Breakdown</h2>
    <canvas id="chart" height="90"></canvas>
  </div>
  <div class="chart-box" style="margin-top: 24px;">
    <h2>Transaction Search</h2>
    <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;">
      <input type="text" id="txSearch" placeholder="Enter Transaction Reference..." style="flex:1;min-width:180px;background:#020817;border:1px solid #334155;color:#f8fafc;padding:10px 12px;border-radius:8px;">
      <button onclick="searchTx()" style="background:#3b82f6;color:white;border:none;padding:10px 16px;border-radius:8px;cursor:pointer;font-weight:600;">Search</button>
    </div>
    <div id="txResults" style="font-size:0.85rem;">
      <table style="width:100%;border-collapse:collapse;display:none;margin-top:10px;" id="txTable">
        <thead>
          <tr style="text-align:left;color:#94a3b8;border-bottom:1px solid #334155;">
            <th style="padding:8px 4px;">Reference</th>
            <th style="padding:8px 4px;">Type</th>
            <th style="padding:8px 4px;">Amount</th>
            <th style="padding:8px 4px;">Status</th>
            <th style="padding:8px 4px;">Date</th>
          </tr>
        </thead>
        <tbody id="txBody"></tbody>
      </table>
      <div id="txEmpty" style="color:#64748b;text-align:center;padding:20px;">Enter a reference number to search</div>
    </div>
  </div>
  <div id="toast" class="toast">Copied!</div>
  <div id="status"></div>
</div>
<script>
const fmt = (n) => '$' + n.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2});
const DASHBOARD_CACHE_KEY = 'proxypay-financial-dashboard-cache-v1';
const TX_CACHE_PREFIX = 'proxypay-financial-tx-cache-v1:';
let deferredPrompt = null;

function renderCachedDashboard(cache) {
  if (!cache || !cache.totals || !Array.isArray(cache.rows)) return;
  const { totals, rows } = cache;
  document.getElementById('totalFees').textContent = fmt(totals.feesCollected);
  document.getElementById('totalCosts').textContent = fmt(totals.providerCosts);
  document.getElementById('totalProfit').textContent = fmt(totals.netProfit);
  document.getElementById('totalProfit').className = 'value ' + (totals.netProfit >= 0 ? 'green' : 'red');

  if (window.Chart) {
    const labels = rows.map(r => r.date);
    new Chart(document.getElementById('chart'), {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {label:'Fees Collected', data: rows.map(r=>r.feesCollected), backgroundColor:'rgba(52,211,153,.7)', borderRadius:3},
          {label:'Provider Costs', data: rows.map(r=>r.providerCosts), backgroundColor:'rgba(248,113,113,.7)', borderRadius:3},
          {label:'Net Profit', data: rows.map(r=>r.netProfit), type:'line', borderColor:'#60a5fa', backgroundColor:'rgba(96,165,250,.15)', tension:.3, fill:true, pointRadius:3},
        ]
      },
      options: {
        responsive:true,
        interaction:{mode:'index',intersect:false},
        plugins:{legend:{labels:{color:'#94a3b8',font:{size:12}}}},
        scales:{
          x:{ticks:{color:'#64748b',maxRotation:45},grid:{color:'rgba(255,255,255,.05)'}},
          y:{ticks:{color:'#64748b',callback:v=>'\$'+v.toLocaleString()},grid:{color:'rgba(255,255,255,.05)'}}
        }
      }
    });
  }

  document.getElementById('status').textContent = 'Offline cached data • ' + new Date(cache.cachedAt).toLocaleTimeString();
}

function saveDashboardCache(data) {
  localStorage.setItem(DASHBOARD_CACHE_KEY, JSON.stringify({ ...data, cachedAt: Date.now() }));
}

function renderTxResults(searchKey, data) {
  const table = document.getElementById('txTable');
  const body = document.getElementById('txBody');
  const empty = document.getElementById('txEmpty');

  if (!data || data.length === 0) {
    empty.textContent = 'No transaction found with reference: ' + searchKey;
    return;
  }

  localStorage.setItem(TX_CACHE_PREFIX + searchKey.toLowerCase(), JSON.stringify({ data, cachedAt: Date.now() }));

  body.innerHTML = '';
  data.forEach(tx => {
    const tr = document.createElement('tr');
    tr.style.borderBottom = '1px solid #1e293b';
    const statusBg = tx.status === 'completed' ? 'rgba(52,211,153,.2)' :
                     tx.status === 'pending' ? 'rgba(250,204,21,.2)' :
                     tx.status === 'failed' ? 'rgba(248,113,113,.2)' : 'rgba(148,163,184,.2)';
    const statusColor = tx.status === 'completed' ? '#34d399' :
                       tx.status === 'pending' ? '#fbbf24' :
                       tx.status === 'failed' ? '#f87171' : '#94a3b8';

    tr.innerHTML = \`
      <td style="padding:12px 4px;font-family:monospace;color:#60a5fa">
        <span class="ref-text">\${tx.referenceNumber}</span>
        <span class="copy-icon" title="Copy reference" onclick="copyRef('\${tx.referenceNumber}')" style="margin-left:8px">📋</span>
      </td>
      <td style="padding:12px 4px;text-transform:capitalize;">\${tx.type}</td>
      <td style="padding:12px 4px;font-weight:600;">\${tx.amount}</td>
      <td style="padding:12px 4px;"><span style="padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600;background:\${statusBg};color:\${statusColor}">\${tx.status.toUpperCase()}</span></td>
      <td style="padding:12px 4px;color:#64748b">\${new Date(tx.createdAt).toLocaleDateString()}</td>
    \`;
    body.appendChild(tr);
  });

  table.style.display = 'table';
  empty.style.display = 'none';
}

async function load() {
  const cached = localStorage.getItem(DASHBOARD_CACHE_KEY);
  if (cached) {
    try { renderCachedDashboard(JSON.parse(cached)); } catch (error) { console.warn('Dashboard cache invalid', error); }
  }

  try {
    const r = await fetch('/api/admin/financial/pnl', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const {rows, totals} = await r.json();
    saveDashboardCache({ rows, totals });

    document.getElementById('totalFees').textContent = fmt(totals.feesCollected);
    document.getElementById('totalCosts').textContent = fmt(totals.providerCosts);
    document.getElementById('totalProfit').textContent = fmt(totals.netProfit);
    document.getElementById('totalProfit').className = 'value ' + (totals.netProfit >= 0 ? 'green' : 'red');

    const labels = rows.map(r => r.date);
    new Chart(document.getElementById('chart'), {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {label:'Fees Collected', data: rows.map(r=>r.feesCollected), backgroundColor:'rgba(52,211,153,.7)', borderRadius:3},
          {label:'Provider Costs', data: rows.map(r=>r.providerCosts), backgroundColor:'rgba(248,113,113,.7)', borderRadius:3},
          {label:'Net Profit', data: rows.map(r=>r.netProfit), type:'line', borderColor:'#60a5fa', backgroundColor:'rgba(96,165,250,.15)', tension:.3, fill:true, pointRadius:3},
        ]
      },
      options: {
        responsive:true,
        interaction:{mode:'index',intersect:false},
        plugins:{legend:{labels:{color:'#94a3b8',font:{size:12}}}},
        scales:{
          x:{ticks:{color:'#64748b',maxRotation:45},grid:{color:'rgba(255,255,255,.05)'}},
          y:{ticks:{color:'#64748b',callback:v=>'\$'+v.toLocaleString()},grid:{color:'rgba(255,255,255,.05)'}}
        }
      }
    });

    document.getElementById('status').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch(e) {
    const cached = localStorage.getItem(DASHBOARD_CACHE_KEY);
    if (cached) {
      try {
        renderCachedDashboard(JSON.parse(cached));
        return;
      } catch (error) {
        console.warn('Unable to render offline cache', error);
      }
    }
    document.querySelector('.chart-box').innerHTML = '<div class="error">Failed to load data: ' + e.message + '</div>';
  }
}

function copyRef(ref) {
   navigator.clipboard.writeText(ref).then(() => {
     const toast = document.getElementById('toast');
     toast.classList.add('show');
     setTimeout(() => toast.classList.remove('show'), 2000);
   }).catch(err => {
     console.error('Failed to copy:', err);
   });
 }

 async function searchTx() {
  const ref = document.getElementById('txSearch').value.trim();
  if (!ref) return;
  
  const table = document.getElementById('txTable');
  const body = document.getElementById('txBody');
  const empty = document.getElementById('txEmpty');
  
  empty.textContent = 'Searching...';
  empty.style.display = 'block';
  table.style.display = 'none';

  const cachedKey = TX_CACHE_PREFIX + ref.toLowerCase();
  const cachedTx = localStorage.getItem(cachedKey);
  if (cachedTx) {
    try {
      renderTxResults(ref, JSON.parse(cachedTx).data);
      return;
    } catch (error) {
      console.warn('Tx cache invalid', error);
    }
  }
  
  try {
    const r = await fetch('/api/admin/transactions?reference=' + encodeURIComponent(ref), {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const {data} = await r.json();
    renderTxResults(ref, data || []);
  } catch (e) {
    const cachedTxFallback = localStorage.getItem(cachedKey);
    if (cachedTxFallback) {
      try {
        renderTxResults(ref, JSON.parse(cachedTxFallback).data);
        return;
      } catch (error) {
        console.warn('Cached tx fallback invalid', error);
      }
    }
    empty.textContent = 'Error: ' + e.message;
  }
}

document.getElementById('txSearch').onkeydown = (e) => { if(e.key === 'Enter') searchTx(); };

const installBtn = document.getElementById('installBtn');
window.addEventListener('beforeinstallprompt', (event) => {
  event.preventDefault();
  deferredPrompt = event;
  installBtn.classList.add('visible');
});

installBtn.addEventListener('click', async () => {
  if (!deferredPrompt) return;
  deferredPrompt.prompt();
  const { outcome } = await deferredPrompt.userChoice;
  if (outcome === 'accepted') {
    installBtn.classList.remove('visible');
  }
  deferredPrompt = null;
});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/api/admin/financial/dashboard/sw.js', { scope: '/api/admin/financial/dashboard/' }).catch((error) => {
      console.warn('Service worker registration failed:', error);
    });
  });
}

load();
setInterval(load, 60000);
</script>
</body>
</html>`);
  },
);

type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; message: string };

const complianceStatuses: ComplianceDocumentStatus[] = [
  "draft",
  "published",
  "archived",
];

const normalizeString = (
  value: unknown,
  field: string,
  required: boolean,
): ValidationResult<string | null | undefined> => {
  if (value === undefined) return { ok: true, value: undefined };
  if (value === null)
    return required
      ? { ok: false, message: `${field} is required` }
      : { ok: true, value: null };
  if (typeof value !== "string")
    return { ok: false, message: `${field} must be a string` };

  const trimmed = value.trim();
  if (required && trimmed.length === 0)
    return { ok: false, message: `${field} is required` };

  return { ok: true, value: trimmed.length === 0 ? null : trimmed };
};

const getCountryValue = (source: Record<string, unknown>) => {
  if (Object.prototype.hasOwnProperty.call(source, "countryCode"))
    return source.countryCode;
  if (Object.prototype.hasOwnProperty.call(source, "country_code"))
    return source.country_code;
  return source.country;
};

const normalizeCountry = (
  value: unknown,
): ValidationResult<string | null | undefined> => {
  if (value === undefined) return { ok: true, value: undefined };
  if (value === null) return { ok: true, value: null };
  if (typeof value !== "string")
    return { ok: false, message: "country must be a string" };

  const normalized = value.trim().toUpperCase();
  if (normalized.length === 0) return { ok: true, value: null };
  if (!/^[A-Z]{2}$/.test(normalized)) {
    return { ok: false, message: "country must be a 2-letter code" };
  }

  return { ok: true, value: normalized };
};

const normalizeTags = (
  value: unknown,
): ValidationResult<string[] | undefined> => {
  if (value === undefined) return { ok: true, value: undefined };

  const rawTags = typeof value === "string" ? value.split(",") : value;
  if (!Array.isArray(rawTags))
    return {
      ok: false,
      message: "tags must be an array or comma-separated string",
    };

  const tags: string[] = [];
  for (const tag of rawTags) {
    if (typeof tag !== "string")
      return { ok: false, message: "tags must contain only strings" };
    const normalized = tag.trim().toLowerCase();
    if (normalized.length > 0 && !tags.includes(normalized))
      tags.push(normalized);
  }

  return { ok: true, value: tags };
};

const normalizeStatus = (
  value: unknown,
): ValidationResult<ComplianceDocumentStatus | undefined> => {
  if (value === undefined) return { ok: true, value: undefined };
  if (
    typeof value !== "string" ||
    !complianceStatuses.includes(value as ComplianceDocumentStatus)
  ) {
    return {
      ok: false,
      message: "status must be draft, published, or archived",
    };
  }

  return { ok: true, value: value as ComplianceDocumentStatus };
};

const validateComplianceCreate = (
  body: Record<string, unknown>,
): ValidationResult<ComplianceDocumentCreateInput> => {
  const title = normalizeString(body.title, "title", true);
  if (!title.ok)
    return title as ValidationResult<ComplianceDocumentCreateInput>;

  const docBody = normalizeString(body.body, "body", true);
  if (!docBody.ok)
    return docBody as ValidationResult<ComplianceDocumentCreateInput>;

  const summary = normalizeString(body.summary, "summary", false);
  if (!summary.ok)
    return summary as ValidationResult<ComplianceDocumentCreateInput>;

  const provider = normalizeString(body.provider, "provider", false);
  if (!provider.ok)
    return provider as ValidationResult<ComplianceDocumentCreateInput>;
  if (provider.value && provider.value.length > 100) {
    return { ok: false, message: "provider must be 100 characters or fewer" };
  }

  const sourceUrl = normalizeString(
    body.sourceUrl ?? body.source_url,
    "sourceUrl",
    false,
  );
  if (!sourceUrl.ok)
    return sourceUrl as ValidationResult<ComplianceDocumentCreateInput>;

  const country = normalizeCountry(getCountryValue(body));
  if (!country.ok)
    return country as ValidationResult<ComplianceDocumentCreateInput>;

  const tags = normalizeTags(body.tags);
  if (!tags.ok) return tags as ValidationResult<ComplianceDocumentCreateInput>;

  const status = normalizeStatus(body.status);
  if (!status.ok)
    return status as ValidationResult<ComplianceDocumentCreateInput>;

  return {
    ok: true,
    value: {
      title: title.value as string,
      body: docBody.value as string,
      summary: summary.value ?? null,
      provider: provider.value ?? null,
      sourceUrl: sourceUrl.value ?? null,
      countryCode: country.value ?? null,
      tags: tags.value ?? [],
      status: status.value,
    },
  };
};

const validateComplianceUpdate = (
  body: Record<string, unknown>,
): ValidationResult<ComplianceDocumentUpdateInput> => {
  const allowedFields = new Set([
    "title",
    "summary",
    "body",
    "country",
    "countryCode",
    "country_code",
    "provider",
    "tags",
    "sourceUrl",
    "source_url",
    "status",
  ]);
  const invalidField = Object.keys(body).find((key) => !allowedFields.has(key));
  if (invalidField)
    return { ok: false, message: `Invalid field: ${invalidField}` };

  const input: ComplianceDocumentUpdateInput = {};

  if (Object.prototype.hasOwnProperty.call(body, "title")) {
    const title = normalizeString(body.title, "title", true);
    if (!title.ok)
      return title as ValidationResult<ComplianceDocumentUpdateInput>;
    input.title = title.value as string;
  }

  if (Object.prototype.hasOwnProperty.call(body, "body")) {
    const docBody = normalizeString(body.body, "body", true);
    if (!docBody.ok)
      return docBody as ValidationResult<ComplianceDocumentUpdateInput>;
    input.body = docBody.value as string;
  }

  if (Object.prototype.hasOwnProperty.call(body, "summary")) {
    const summary = normalizeString(body.summary, "summary", false);
    if (!summary.ok)
      return summary as ValidationResult<ComplianceDocumentUpdateInput>;
    input.summary = summary.value ?? null;
  }

  if (Object.prototype.hasOwnProperty.call(body, "provider")) {
    const provider = normalizeString(body.provider, "provider", false);
    if (!provider.ok)
      return provider as ValidationResult<ComplianceDocumentUpdateInput>;
    if (provider.value && provider.value.length > 100) {
      return { ok: false, message: "provider must be 100 characters or fewer" };
    }
    input.provider = provider.value ?? null;
  }

  if (
    Object.prototype.hasOwnProperty.call(body, "sourceUrl") ||
    Object.prototype.hasOwnProperty.call(body, "source_url")
  ) {
    const sourceUrl = normalizeString(
      body.sourceUrl ?? body.source_url,
      "sourceUrl",
      false,
    );
    if (!sourceUrl.ok)
      return sourceUrl as ValidationResult<ComplianceDocumentUpdateInput>;
    input.sourceUrl = sourceUrl.value ?? null;
  }

  if (
    Object.prototype.hasOwnProperty.call(body, "country") ||
    Object.prototype.hasOwnProperty.call(body, "countryCode") ||
    Object.prototype.hasOwnProperty.call(body, "country_code")
  ) {
    const country = normalizeCountry(getCountryValue(body));
    if (!country.ok)
      return country as ValidationResult<ComplianceDocumentUpdateInput>;
    input.countryCode = country.value ?? null;
  }

  if (Object.prototype.hasOwnProperty.call(body, "tags")) {
    const tags = normalizeTags(body.tags);
    if (!tags.ok)
      return tags as ValidationResult<ComplianceDocumentUpdateInput>;
    input.tags = tags.value ?? [];
  }

  if (Object.prototype.hasOwnProperty.call(body, "status")) {
    const status = normalizeStatus(body.status);
    if (!status.ok)
      return status as ValidationResult<ComplianceDocumentUpdateInput>;
    input.status = status.value;
  }

  if (Object.keys(input).length === 0)
    return { ok: false, message: "At least one field is required" };

  return { ok: true, value: input };
};

const getQueryString = (value: unknown) => {
  if (Array.isArray(value)) return value[0];
  return typeof value === "string" ? value.trim() : undefined;
};

const parsePositiveInt = (value: unknown, fallback: number, max?: number) => {
  const raw = getQueryString(value);
  const parsed = raw ? parseInt(raw, 10) : fallback;
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return max ? Math.min(parsed, max) : parsed;
};

router.get(
  "/compliance/knowledge-base",
  requireAdmin,
  (_req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compliance Knowledge Base</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}h1{font-size:1.4rem;font-weight:600;margin-bottom:8px;color:#f8fafc}.sub{color:#94a3b8;margin-bottom:20px}.grid{display:grid;grid-template-columns:340px 1fr;gap:18px}.panel{background:#1e293b;border-radius:10px;padding:18px}.row{display:flex;gap:8px;margin-bottom:10px}input,select,textarea{width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:9px 11px;border-radius:6px}textarea{min-height:120px;resize:vertical}button{background:#3b82f6;color:white;border:none;padding:9px 13px;border-radius:6px;cursor:pointer;font-weight:600}button.secondary{background:#475569}button.danger{background:#dc2626}.doc{border-bottom:1px solid #334155;padding:13px 0;cursor:pointer}.doc:hover h3{color:#93c5fd}.doc h3{font-size:1rem;margin-bottom:5px}.meta,.empty{font-size:.8rem;color:#94a3b8}.pill{display:inline-block;background:#334155;color:#cbd5e1;border-radius:999px;padding:2px 8px;margin:4px 4px 0 0;font-size:.72rem}.status{float:right;text-transform:uppercase;color:#60a5fa}.actions{display:flex;gap:8px;margin-top:12px}.message{margin-top:10px;color:#94a3b8;font-size:.85rem}.error{color:#f87171}.success{color:#34d399}@media(max-width:900px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>Compliance Knowledge Base</h1>
<div class="sub">Local-law and regulation document portal for admin teams.</div>
<div class="grid">
  <div class="panel">
    <div class="row"><input id="search" placeholder="Search title, body, provider, tags"><button onclick="loadDocs()">Search</button></div>
    <div class="row"><select id="country"><option value="">All countries</option></select><select id="provider"><option value="">All providers</option></select></div>
    <div class="row"><select id="tag"><option value="">All tags</option></select><select id="status"><option value="">Active docs</option><option>draft</option><option>published</option><option>archived</option></select></div>
    <div id="docs"></div>
  </div>
  <div class="panel">
    <input id="docId" type="hidden">
    <div class="row"><input id="title" placeholder="Title"><select id="docStatus"><option>published</option><option>draft</option><option>archived</option></select></div>
    <div class="row"><input id="docCountry" placeholder="Country code"><input id="docProvider" placeholder="Provider"></div>
    <input id="docTags" placeholder="Tags, comma separated" style="margin-bottom:10px">
    <input id="sourceUrl" placeholder="Source URL" style="margin-bottom:10px">
    <textarea id="summary" placeholder="Summary" style="margin-bottom:10px"></textarea>
    <textarea id="body" placeholder="Document body"></textarea>
    <div class="actions"><button onclick="saveDoc()">Save</button><button class="secondary" onclick="resetForm()">New</button><button class="danger" onclick="archiveDoc()">Archive</button></div>
    <div id="message" class="message"></div>
  </div>
</div>
<script>
const api = '/api/admin/compliance/docs';
const el = id => document.getElementById(id);
function esc(v){return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function params(){const p = new URLSearchParams();['search','country','provider','tag','status'].forEach(id => {const v = el(id).value.trim(); if(v) p.set(id, v);}); return p;}
function setMessage(text, cls){el('message').className = 'message ' + (cls || ''); el('message').textContent = text;}
async function loadFacets(){const r = await fetch(api + '/facets', {credentials:'include'}); if(!r.ok) return; const f = await r.json(); fill('country', f.countries); fill('provider', f.providers); fill('tag', f.tags);}
function fill(id, values){const first = el(id).options[0].outerHTML; el(id).innerHTML = first + (values || []).map(v => '<option value="' + esc(v) + '">' + esc(v) + '</option>').join('');}
async function loadDocs(){const r = await fetch(api + '?' + params().toString(), {credentials:'include'}); const box = el('docs'); if(!r.ok){box.innerHTML='<div class="empty error">Failed to load documents</div>'; return;} const json = await r.json(); if(!json.data.length){box.innerHTML='<div class="empty">No documents found</div>'; return;} box.innerHTML = json.data.map(d => '<div class="doc" onclick="openDoc(\'' + d.id + '\')"><span class="status">' + esc(d.status) + '</span><h3>' + esc(d.title) + '</h3><div class="meta">' + esc(d.countryCode || 'Global') + ' · ' + esc(d.provider || 'Any provider') + '</div><div>' + (d.tags || []).map(t => '<span class="pill">' + esc(t) + '</span>').join('') + '</div></div>').join('');}
async function openDoc(id){const r = await fetch(api + '/' + encodeURIComponent(id), {credentials:'include'}); if(!r.ok){setMessage('Document not found','error'); return;} const d = await r.json(); el('docId').value=d.id; el('title').value=d.title || ''; el('docStatus').value=d.status || 'published'; el('docCountry').value=d.countryCode || ''; el('docProvider').value=d.provider || ''; el('docTags').value=(d.tags || []).join(', '); el('sourceUrl').value=d.sourceUrl || ''; el('summary').value=d.summary || ''; el('body').value=d.body || ''; setMessage('Loaded document','');}
async function saveDoc(){const id = el('docId').value; const payload = {title:el('title').value, status:el('docStatus').value, country:el('docCountry').value, provider:el('docProvider').value, tags:el('docTags').value, sourceUrl:el('sourceUrl').value, summary:el('summary').value, body:el('body').value}; const r = await fetch(id ? api + '/' + encodeURIComponent(id) : api, {method:id?'PATCH':'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body:JSON.stringify(payload)}); const json = await r.json().catch(()=>({})); if(!r.ok){setMessage(json.message || 'Save failed','error'); return;} setMessage('Saved','success'); el('docId').value=json.id; await loadFacets(); await loadDocs();}
async function archiveDoc(){const id = el('docId').value; if(!id) return setMessage('Select a document first','error'); const r = await fetch(api + '/' + encodeURIComponent(id), {method:'DELETE', credentials:'include'}); if(!r.ok){setMessage('Archive failed','error'); return;} setMessage('Archived','success'); resetForm(); await loadFacets(); await loadDocs();}
function resetForm(){['docId','title','docCountry','docProvider','docTags','sourceUrl','summary','body'].forEach(id=>el(id).value=''); el('docStatus').value='published';}
['country','provider','tag','status'].forEach(id => el(id).onchange = loadDocs); el('search').onkeydown = e => { if(e.key === 'Enter') loadDocs(); };
loadFacets(); loadDocs();
</script>
</body>
</html>`);
  },
);

router.get(
  "/compliance/docs",
  requireAdmin,
  async (req: Request, res: Response) => {
    try {
      const page = parsePositiveInt(req.query.page, 1);
      const limit = parsePositiveInt(req.query.limit, 25, 100);
      const country = normalizeCountry(getQueryString(req.query.country));
      if (!country.ok) {
        const err = country as { ok: false; message: string };
        throw createError(ERROR_CODES.INVALID_INPUT, err.message, {
          message: err.message,
        });
      }

      const status = normalizeStatus(getQueryString(req.query.status));
      if (!status.ok) {
        const err = status as { ok: false; message: string };
        throw createError(ERROR_CODES.INVALID_INPUT, err.message, {
          message: err.message,
        });
      }

      const result = await complianceDocumentModel.list({
        country: country.value || undefined,
        provider: getQueryString(req.query.provider) || undefined,
        tag: getQueryString(req.query.tag)?.toLowerCase() || undefined,
        status: status.value,
        search: getQueryString(req.query.search) || undefined,
        limit,
        offset: (page - 1) * limit,
      });

      res.json({
        data: result.documents,
        pagination: {
          total: result.total,
          page,
          limit,
          totalPages: Math.ceil(result.total / limit),
        },
      });
    } catch (error) {
      console.error("[compliance/docs:list]", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to list compliance documents",
      );
    }
  },
);

router.get(
  "/compliance/docs/facets",
  requireAdmin,
  async (_req: Request, res: Response) => {
    try {
      res.json(await complianceDocumentModel.getFacets());
    } catch (error) {
      console.error("[compliance/docs:facets]", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch compliance document facets",
        {
          message: "Failed to fetch compliance document facets",
        },
      );
    }
  },
);

router.get(
  "/compliance/docs/:id",
  requireAdmin,
  async (req: Request, res: Response) => {
    try {
      const document = await complianceDocumentModel.findById(req.params.id);
      if (!document) {
        throw createError(
          ERROR_CODES.NOT_FOUND,
          "Compliance document not found",
          {
            message: "Compliance document not found",
          },
        );
      }
      res.json(document);
    } catch (error) {
      console.error("[compliance/docs:get]", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch compliance document",
      );
    }
  },
);

router.post(
  "/compliance/docs",
  requireAdmin,
  logAdminAction("CREATE_COMPLIANCE_DOCUMENT"),
  async (req: Request, res: Response) => {
    try {
      const validation = validateComplianceCreate(req.body ?? {});
      if (!validation.ok) {
        const err = validation as { ok: false; message: string };
        throw createError(ERROR_CODES.INVALID_INPUT, err.message, {
          message: err.message,
        });
      }

      const adminUser = (req as AuthRequest).user;
      const document = await complianceDocumentModel.create(
        validation.value,
        adminUser?.id,
      );
      res.status(201).json(document);
    } catch (error) {
      console.error("[compliance/docs:create]", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to create compliance document",
      );
    }
  },
);

router.patch(
  "/compliance/docs/:id",
  requireAdmin,
  logAdminAction("UPDATE_COMPLIANCE_DOCUMENT"),
  async (req: Request, res: Response) => {
    try {
      const validation = validateComplianceUpdate(req.body ?? {});
      if (!validation.ok) {
        const err = validation as { ok: false; message: string };
        throw createError(ERROR_CODES.INVALID_INPUT, err.message, {
          message: err.message,
        });
      }

      const adminUser = (req as AuthRequest).user;
      const document = await complianceDocumentModel.update(
        req.params.id,
        validation.value,
        adminUser?.id,
      );
      if (!document) {
        throw createError(
          ERROR_CODES.NOT_FOUND,
          "Compliance document not found",
          {
            message: "Compliance document not found",
          },
        );
      }
      res.json(document);
    } catch (error) {
      console.error("[compliance/docs:update]", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to update compliance document",
      );
    }
  },
);

/**
 * =========================
 * STELLAR OPERATIONS
 * =========================
 */

// POST /api/admin/stellar/enable-clawback
router.post(
  "/stellar/enable-clawback",
  requireAdmin,
  requireSuperAdmin,
  logAdminAction("ENABLE_STELLAR_CLAWBACK"),
  async (_req: Request, res: Response) => {
    try {
      const stellarService = new StellarService();
      await stellarService.enableClawback();
      res.json({ message: "Clawback capability enabled on issuance account" });
    } catch (err) {
      console.error("Error enabling clawback:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to enable clawback capability",
        {
          message: "Failed to enable clawback capability",
          error: err instanceof Error ? err.message : "Unknown error",
        },
      );
    }
  },
);

// POST /api/admin/stellar/clawback
router.post(
  "/stellar/clawback",
  requireAdmin,
  logAdminAction("EXECUTE_STELLAR_CLAWBACK"),
  async (req: Request, res: Response) => {
    try {
      const { transactionId, reason } = req.body;

      if (!transactionId) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "transactionId is required",
          {
            message: "transactionId is required",
          },
        );
      }
      if (!reason) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "reason is required for clawback",
          {
            message: "reason is required for clawback",
          },
        );
      }

      const transaction = await transactionModel.findById(transactionId);
      if (!transaction) {
        throw createError(ERROR_CODES.NOT_FOUND, "Transaction not found", {
          message: "Transaction not found",
        });
      }

      if (transaction.status !== TransactionStatus.Completed) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          `Cannot claw back transaction in status: ${transaction.status}`,
          {
            message: `Cannot claw back transaction in status: ${transaction.status}`,
          },
        );
      }

      const stellarService = new StellarService();
      const { hash } = await stellarService.executeClawback(
        transaction.stellarAddress,
        transaction.amount,
      );

      // Handle accounting reversal
      await ledgerService.postClawback(
        parseFloat(transaction.amount),
        transaction.referenceNumber,
        transaction.id,
        (req as AuthRequest).user?.id || "admin",
        reason,
      );

      // Update transaction status
      await transactionModel.updateStatus(
        transactionId,
        TransactionStatus.ClawedBack,
      );

      res.json({
        message: "Transaction clawed back successfully",
        stellarHash: hash,
        transactionId,
      });
    } catch (err) {
      // #647: the destination account or its trustline is gone on Stellar, so
      // the clawback cannot be issued. Report it as a validation failure with a
      // precise reason instead of a generic 500.
      if (err instanceof ClawbackDestinationError) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          err.message,
          {
            message: err.message,
            error: err.message,
            clawbackFailure: err.failure,
          },
        );
      }
      console.error("Error executing clawback:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to execute clawback",
        {
          message: "Failed to execute clawback",
          error: err instanceof Error ? err.message : "Unknown error",
        },
      );
    }
  },
);

// POST /api/admin/stellar/batch-payment
router.post(
  "/stellar/batch-payment",
  requireAdmin,
  logAdminAction("EXECUTE_STELLAR_BATCH_PAYMENT"),
  async (req: Request, res: Response) => {
    try {
      const { payments } = req.body; // Array of { destination, amount, memo }

      if (!Array.isArray(payments) || payments.length === 0) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "payments array is required and cannot be empty",
          {
            message: "payments array is required and cannot be empty",
          },
        );
      }

      if (payments.length > 50) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "Maximum 50 payments per batch allowed",
          {
            message: "Maximum 50 payments per batch allowed",
          },
        );
      }

      // Initialize HighThroughputService if needed
      if (!highThroughputService.isServiceInitialized()) {
        await highThroughputService.initialize();
      }

      const stellarIssuerSecret = process.env.STELLAR_ISSUER_SECRET;
      if (!stellarIssuerSecret) {
        throw new Error("STELLAR_ISSUER_SECRET not configured");
      }

      const issuerPublicKey =
        StellarSdk.Keypair.fromSecret(stellarIssuerSecret).publicKey();

      // 1. Create transactions in DB
      const transactionIds: string[] = [];
      for (const p of payments) {
        const tx = await transactionModel.create({
          type: "payment",
          amount: p.amount,
          stellarAddress: p.destination,
          provider: "stellar",
          status: TransactionStatus.Pending,
          metadata: { memo: p.memo, batch: true },
        });
        transactionIds.push(tx.id);
      }

      // 2. Prepare payments for HighThroughputService
      const paymentOptions = payments.map((p, index) => ({
        sourceAccount: issuerPublicKey,
        sourceSecret: stellarIssuerSecret,
        destination: p.destination,
        amount: p.amount,
        asset: "native" as const, // Or configured asset
        memo: p.memo,
        useFeeBump: true, // Key feature requirement
      }));

      // 3. Submit batch
      const batchResult =
        await highThroughputService.submitBatchPayments(paymentOptions);

      // 4. Update DB status based on results
      for (let i = 0; i < batchResult.results.length; i++) {
        const result = batchResult.results[i];
        const txId = transactionIds[i];

        if (result.success) {
          await transactionModel.updateStatus(
            txId,
            TransactionStatus.Completed,
          );
          await transactionModel.updateMetadata(txId, {
            ...payments[i].metadata,
            stellar: { transactionHash: result.hash },
          });
        } else {
          await transactionModel.updateStatus(txId, TransactionStatus.Failed);
          await transactionModel.updateMetadata(txId, {
            ...payments[i].metadata,
            error: result.error,
          });
        }
      }

      res.json({
        message: "Batch payment processed",
        successful: batchResult.successful,
        failed: batchResult.failed,
        results: batchResult.results,
        totalTimeMs: batchResult.totalTimeMs,
      });
    } catch (err) {
      console.error("Error executing batch payment:", err);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to execute batch payment",
        {
          message: "Failed to execute batch payment",
          error: err instanceof Error ? err.message : "Unknown error",
        },
      );
    }
  },
);

router.delete(
  "/compliance/docs/:id",
  requireAdmin,
  logAdminAction("ARCHIVE_COMPLIANCE_DOCUMENT"),
  async (req: Request, res: Response) => {
    try {
      const adminUser = (req as AuthRequest).user;
      const document = await complianceDocumentModel.archive(
        req.params.id,
        adminUser?.id,
      );
      if (!document) {
        throw createError(
          ERROR_CODES.NOT_FOUND,
          "Compliance document not found",
          {
            message: "Compliance document not found",
          },
        );
      }
      res.json(document);
    } catch (error) {
      console.error("[compliance/docs:archive]", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to archive compliance document",
      );
    }
  },
);

// =========================
// PROVIDER SETTINGS
// =========================

router.get(
  "/provider-settings",
  requireAdmin,
  logAdminAction("GET_PROVIDER_SETTINGS"),
  async (req: Request, res: Response) => {
    try {
      const settings = await providerSettingsService.getAllSettings();
      res.json(settings);
    } catch (error) {
      console.error("Error fetching provider settings:", error);
      res.status(500).json({ message: "Failed to fetch provider settings" });
    }
  },
);

router.put(
  "/provider-settings/:providerName",
  requireAdmin,
  logAdminAction("UPDATE_PROVIDER_SETTINGS"),
  async (req: Request, res: Response) => {
    try {
      const providerName = req.params.providerName;
      const { failure_threshold, timeout_ms, fallback_order } = req.body;

      const settings = await providerSettingsService.upsertProviderSettings(
        providerName,
        failure_threshold || 3,
        timeout_ms || 5000,
        fallback_order || null,
      );

      resetCircuitBreakerForProvider(providerName);

      res.json({ message: "Provider settings updated successfully", settings });
    } catch (error) {
      console.error("Error updating provider settings:", error);
      res.status(500).json({ message: "Failed to update provider settings" });
    }
  },
);

/**
 * =========================
 * DASHBOARD & MONITORING
 * =========================
 */

/**
 * GET /api/admin/dashboard/stats
 * Comprehensive dashboard statistics for CLI/UI
 */
router.get(
  "/dashboard/stats",
  requireAdmin,
  logAdminAction("GET_DASHBOARD_STATS"),
  async (req: Request, res: Response) => {
    try {
      const startTime = Date.now();
      const timestamp = new Date().toISOString();

      // Fetch system health in parallel
      const [
        queueStats,
        databaseHealth,
        redisHealth,
        transactionStats,
        providerHealth,
      ] = await Promise.all([
        getQueueStats().catch((err) => {
          console.error("[Dashboard] Queue stats error:", err);
          return {
            pending: 0,
            active: 0,
            completed: 0,
            failed: 0,
            total: 0,
          };
        }),
        checkReplicaHealth()
          .then((replicas) => ({
            status: "healthy" as const,
            replicas,
          }))
          .catch((err) => {
            console.error("[Dashboard] Database health error:", err);
            return { status: "unhealthy" as const, replicas: [] };
          }),
        redisClient
          .ping()
          .then(() => ({ status: "healthy" as const, responseTime: 0 }))
          .catch((err) => {
            console.error("[Dashboard] Redis health error:", err);
            return { status: "unhealthy" as const, responseTime: undefined };
          }),
        (async () => {
          const stats = await (transactionModel as any).getStatistics(
            new Date(Date.now() - 24 * 60 * 60 * 1000),
            new Date(),
          );
          return {
            totalCount: stats.totalTransactions,
            successRate: stats.successRate,
            totalVolume: stats.totalVolume,
            activeUsers: await (UserModel as any).countActiveUsers(24),
          };
        })().catch((err) => {
          console.error("[Dashboard] Transaction stats error:", err);
          return {
            totalCount: 0,
            successRate: 0,
            totalVolume: 0,
            activeUsers: 0,
          };
        }),
        (async () => {
          const mobileMoneyService = new MobileMoneyService();
          try {
            return mobileMoneyService.getFailoverStats();
          } catch (err) {
            console.error("[Dashboard] Provider health error:", err);
            return {};
          }
        })(),
      ]);

      const responseTime = Date.now() - startTime;
      const stellarHealthy = transactionStats.totalCount >= 0; // If we can query, Stellar is ok

      res.json({
        timestamp,
        health: {
          database:
            databaseHealth.status === "healthy" ? "healthy" : "unhealthy",
          redis: redisHealth.status === "healthy" ? "healthy" : "unhealthy",
          stellar: stellarHealthy ? "healthy" : "unhealthy",
          responseTime,
        },
        queue: {
          totalJobs: (queueStats as any).total || 0,
          pendingJobs: (queueStats as any).pending || 0,
          activeJobs: (queueStats as any).active || 0,
          completedJobs: (queueStats as any).completed || 0,
          failedJobs: (queueStats as any).failed || 0,
          dlqSize: (queueStats as any).dlq || 0,
        },
        transactions: {
          totalCount: transactionStats.totalCount,
          successRate: transactionStats.successRate,
          totalVolume: transactionStats.totalVolume,
          activeUsers: transactionStats.activeUsers,
        },
        providers: Object.entries(providerHealth).reduce(
          (acc, [provider, stats]: [string, any]) => {
            acc[provider] = {
              status: stats.isHealthy ? "online" : "offline",
              failureRate: stats.failureRate || 0,
              lastChecked: timestamp,
            };
            return acc;
          },
          {} as Record<string, any>,
        ),
      });
    } catch (error) {
      console.error("[Dashboard] Failed to fetch stats:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch dashboard stats",
      );
    }
  },
);

/**
 * GET /api/admin/health
 * Quick health check for monitoring
 */
router.get(
  "/health",
  logAdminAction("GET_HEALTH"),
  async (req: Request, res: Response) => {
    try {
      const startTime = Date.now();

      const [databaseOk, redisOk] = await Promise.all([
        pool
          .query("SELECT 1")
          .then(() => true)
          .catch(() => false),
        redisClient
          .ping()
          .then(() => true)
          .catch(() => false),
      ]);

      const responseTime = Date.now() - startTime;

      res.json({
        database: databaseOk ? "healthy" : "unhealthy",
        redis: redisOk ? "healthy" : "unhealthy",
        stellar: "healthy", // Assume ok unless we detect specific Stellar failures
        responseTime,
      });
    } catch (error) {
      console.error("[Health] Check failed:", error);
      res.status(503).json({
        database: "unhealthy",
        redis: "unhealthy",
        stellar: "unhealthy",
        responseTime: 0,
      });
    }
  },
);

/**
 * GET /api/admin/queue/stats
 * Queue metrics with detailed breakdown
 */
router.get(
  "/queue/stats",
  requireAdmin,
  logAdminAction("GET_QUEUE_STATS"),
  async (req: Request, res: Response) => {
    try {
      const stats = await getQueueStats();

      res.json({
        totalJobs: (stats as any).total || 0,
        pendingJobs: (stats as any).pending || 0,
        activeJobs: (stats as any).active || 0,
        completedJobs: (stats as any).completed || 0,
        failedJobs: (stats as any).failed || 0,
        dlqSize: (stats as any).dlq || 0,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("[Queue] Stats fetch failed:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch queue stats",
      );
    }
  },
);

/**
 * GET /api/admin/api-keys/scope-usage
 * Returns usage statistics for API keys broken down by scope.
 * Lists how many active keys carry each scope, along with the total
 * active/expired/revoked key counts.
 */
router.get(
  "/api-keys/scope-usage",
  requireAdmin,
  logAdminAction("GET_API_KEY_SCOPE_USAGE"),
  async (req: Request, res: Response) => {
    try {
      // Fetch all API keys from the database
      const result = await pool.query<{
        permissions: number;
        is_active: boolean;
        expires_at: string | null;
      }>(`SELECT permissions, is_active, expires_at FROM api_keys`);

      const rows = result.rows;
      const now = new Date();

      let totalActive = 0;
      let totalExpired = 0;
      let totalRevoked = 0;

      // Scope name → count of active keys that carry that scope
      const scopeCounts: Record<string, number> = {};

      // Import scope definitions inline to avoid a circular-dependency risk
      const { ApiKeyScope } = await import("../auth/apikeys");

      for (const row of rows) {
        const expired = row.expires_at ? new Date(row.expires_at) < now : false;

        if (!row.is_active) {
          totalRevoked++;
          continue;
        }
        if (expired) {
          totalExpired++;
          continue;
        }

        totalActive++;

        // Tally each scope bit present in this key's permissions bitmask
        for (const [name, bit] of Object.entries(ApiKeyScope) as Array<
          [string, number]
        >) {
          if ((row.permissions & bit) === bit) {
            scopeCounts[name] = (scopeCounts[name] ?? 0) + 1;
          }
        }
      }

      // Build an ordered list of scope usage entries
      const scopeUsage = Object.entries(ApiKeyScope).map(([name, bit]) => ({
        scope: name,
        bit,
        activeKeyCount: scopeCounts[name] ?? 0,
      }));

      res.json({
        summary: {
          total: rows.length,
          active: totalActive,
          expired: totalExpired,
          revoked: totalRevoked,
        },
        scopeUsage,
        generatedAt: now.toISOString(),
      });
    } catch (error) {
      console.error("[Admin] Scope usage fetch failed:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch API key scope usage",
      );
    }
  },
);

/**
 * GET /api/admin/database/pool-stats
 * Comprehensive connection pool statistics
 */
router.get(
  "/database/pool-stats",
  authenticateToken,
  requirePermission("admin:system"),
  async (_req: Request, res: Response) => {
    try {
      const stats = getConnectionPoolStatistics();
      res.json({ success: true, data: stats });
    } catch (error) {
      console.error("[Admin] Pool stats fetch failed:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch pool statistics",
      );
    }
  },
);

/**
 * GET /api/admin/database/replicas
 * Get current replica statuses
 */
router.get(
  "/database/replicas",
  authenticateToken,
  requirePermission("admin:system"),
  async (_req: Request, res: Response) => {
    try {
      const statuses = getReplicaStatuses();
      res.json({ success: true, data: statuses });
    } catch (error) {
      console.error("[Admin] Replica status fetch failed:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch replica statuses",
      );
    }
  },
);

/**
 * PATCH /api/admin/database/replicas/:index
 * Enable or disable a replica by index
 */
router.patch(
  "/database/replicas/:index",
  authenticateToken,
  requirePermission("admin:system"),
  async (req: Request, res: Response) => {
    try {
      const index = parseInt(req.params.index, 10);
      const { enabled } = req.body as { enabled: boolean };

      if (Number.isNaN(index)) {
        return res.status(400).json({ error: "Index must be a number" });
      }

      const success = setReplicaEnabled(index, enabled);
      if (!success) {
        return res.status(404).json({ error: "Replica index not found" });
      }

      res.json({
        success: true,
        message: `Replica ${index} ${enabled ? "enabled" : "disabled"}`,
      });
    } catch (error) {
      console.error("[Admin] Replica toggle failed:", error);
      throw createError(ERROR_CODES.INTERNAL_ERROR, "Failed to toggle replica");
    }
  },
);

// ---------------------------------------------------------------------------
// Audit log viewer (issue #620)
// ---------------------------------------------------------------------------

const escapeHtml = (value: unknown): string =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

/**
 * Normalize the audit log viewer query params into `searchAuditLogs` filters.
 * Invalid date bounds are rejected so a typo cannot silently return a partial
 * (and therefore misleading) audit trail.
 */
const parseAuditLogFilters = (query: Request["query"]) => {
  const asString = (value: unknown): string | undefined =>
    typeof value === "string" && value.trim().length > 0
      ? value.trim()
      : undefined;

  const from = asString(query.from);
  const to = asString(query.to);

  if (from && Number.isNaN(new Date(from).getTime())) {
    throw createError(
      ERROR_CODES.INVALID_INPUT,
      'Query "from" must be an ISO-8601 date',
      { message: 'Query "from" must be an ISO-8601 date' },
    );
  }

  if (to && Number.isNaN(new Date(to).getTime())) {
    throw createError(
      ERROR_CODES.INVALID_INPUT,
      'Query "to" must be an ISO-8601 date',
      { message: 'Query "to" must be an ISO-8601 date' },
    );
  }

  const limitRaw = asString(query.limit);
  const offsetRaw = asString(query.offset);
  const limit = limitRaw ? parseInt(limitRaw, 10) : 50;
  const offset = offsetRaw ? parseInt(offsetRaw, 10) : 0;

  return {
    adminId: asString(query.adminId ?? query.admin_id),
    action: asString(query.action),
    resource: asString(query.resource),
    resourceId: asString(query.resourceId ?? query.resource_id),
    from,
    to,
    limit: Number.isFinite(limit) && limit > 0 ? limit : 50,
    offset: Number.isFinite(offset) && offset > 0 ? offset : 0,
  };
};

/**
 * Render the audit log rows as a minimal, dependency-free HTML table so the
 * admin dashboard can link straight to a browser view.
 */
const renderAuditLogViewer = (
  logs: Record<string, unknown>[],
  total: number,
): string => {
  const rows = logs
    .map(
      (log) => `<tr>
        <td>${escapeHtml(log.timestamp)}</td>
        <td>${escapeHtml(log.adminId)}</td>
        <td>${escapeHtml(log.action)}</td>
        <td>${escapeHtml(log.resource)}</td>
        <td><code>${escapeHtml(log.resourceId)}</code></td>
        <td><pre>${escapeHtml(JSON.stringify(log.diff ?? {}))}</pre></td>
        <td>${escapeHtml(log.ipAddress)}</td>
      </tr>`,
    )
    .join("\n");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Admin audit log</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 2rem; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #d0d5dd; padding: 0.5rem; text-align: left; vertical-align: top; }
      th { background: #f2f4f7; }
      pre { margin: 0; white-space: pre-wrap; max-width: 32rem; }
    </style>
  </head>
  <body>
    <h1>Admin audit log</h1>
    <p>Showing ${logs.length} of ${total} matching events (newest first).</p>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th><th>Admin</th><th>Action</th><th>Resource</th>
          <th>Resource IDs</th><th>Diff</th><th>IP</th>
        </tr>
      </thead>
      <tbody>
${rows}
      </tbody>
    </table>
  </body>
</html>`;
};

/**
 * GET /api/admin/audit-logs
 *
 * Searchable audit trail used by the admin dashboard (issue #620).
 *
 * Query: adminId?, action?, resource?, resourceId?, from?, to?, limit?, offset?
 */
router.get(
  "/audit-logs",
  requireAdmin,
  logAdminAction("VIEW_AUDIT_LOGS"),
  async (req: Request, res: Response) => {
    try {
      const result = await searchAuditLogs(parseAuditLogFilters(req.query));
      return res.json({ success: true, ...result });
    } catch (error) {
      if ((error as { code?: string })?.code) throw error;
      console.error("Error fetching audit logs:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to fetch audit logs",
        {
          message: "Failed to fetch audit logs",
        },
      );
    }
  },
);

/**
 * GET /api/admin/audit-logs/view
 *
 * HTML rendering of the same search results for quick operator review.
 */
router.get(
  "/audit-logs/view",
  requireAdmin,
  async (req: Request, res: Response) => {
    try {
      const result = await searchAuditLogs(parseAuditLogFilters(req.query));
      return res
        .type("html")
        .send(renderAuditLogViewer(result.logs, result.total));
    } catch (error) {
      if ((error as { code?: string })?.code) throw error;
      console.error("Error rendering audit log view:", error);
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Failed to render audit logs",
        {
          message: "Failed to render audit logs",
        },
      );
    }
  },
);

export { router as adminRoutes };
