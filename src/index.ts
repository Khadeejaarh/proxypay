// Initialize centralized configuration first
import "./config/init";

import "./tracer";
import path from "path";
import express, { NextFunction, Request, Response } from "express";
import { IncomingMessage, Server } from "http";
import compression from "compression";
import dotenv from "dotenv";
import helmet from "helmet";
import * as Sentry from "@sentry/node";
import { register } from "prom-client";
import spdy from "spdy";
import fs from "fs";
import session from "express-session";
import type { SessionOptions } from "express-session";
import {
  apiVersionMiddleware,
  validateVersionMiddleware,
  VersionedRequest,
} from "./middleware/apiVersion";
import { deprecationMiddleware } from "./middleware/deprecation";
import { seedDeprecations } from "./middleware/deprecationSeed";
import { adminDeprecationRoutes } from "./routes/admin/deprecations";
import {
  bulkRoutesV1,
  disputeRoutesV1,
  statsRoutesV1,
  transactionDisputeRoutesV1,
  transactionRoutesV1,
  vaultRoutesV1,
} from "./routes/v1";
import { transactionRoutesV2 } from "./routes/v2";
import { transactionRoutes } from "./routes/transactions";
import { authRoutes } from "./routes/auth";
import { bulkRoutes } from "./routes/bulk";
import { transactionDisputeRoutes, disputeRoutes } from "./routes/disputes";
import { statsRoutes } from "./routes/stats";
import { contactsRoutes } from "./routes/contacts";
import { reportsRoutes } from "./routes/reports";
import feesRoutes from "./routes/fees";
import { createKYCRoutes } from "./routes/kycRoutes";
import { adminRoutes } from "./routes/admin";
import invoiceRoutes from "./routes/invoices";
import webhookCircuitBreakerRoutes from "./routes/webhookCircuitBreaker";
import kycTierUpgradeRoutes from "./routes/kycTierUpgradeRoutes";
import { userRoutes } from "./routes/users";
import { createError, errorHandler } from "./middleware/errorHandler";
import {
  connectRedis,
  disconnectRedis,
  redisClient,
  createRedisStore,
  SESSION_TTL_SECONDS,
} from "./config/redis";
import { rateLimitMiddleware } from "./middleware/rateLimitRedis";
import rateLimitDefaultMiddleware from "./middleware/rateLimit";
import { createOAuthRouter } from "./auth/oauth";
import { getReplicationStatus, pool } from "./config/database";
import {
  globalTimeout,
  haltOnTimedout,
  timeoutErrorHandler,
} from "./middleware/timeout";
import { requireAuth, verifyTokenStateful } from "./middleware/auth";
import { isAccountActive } from "./middleware/checkAccountStatus";
import { responseTime } from "./middleware/responseTime";
import { requestId } from "./middleware/requestId";
import { idempotency } from "./middleware/idempotency";
import { readReplicaRoutingMiddleware } from "./middleware/readReplicaRouting";
import { dbConnectionLeakDetector } from "./middleware/dbConnectionLeakDetector";
import { i18nMiddleware } from "./utils/i18n";
import { metricsMiddleware } from "./middleware/metrics";
import { validateStellarNetwork, logStellarNetwork } from "./config/stellar";
import { sessionAnomalyLogger } from "./services/logger";
import {
  HealthCheckResponse,
  ReadinessCheckResponse,
  ProviderHealthSummary,
} from "./types/api";
import {
  checkMobileMoneyHealth,
  ProviderName,
} from "./services/mobilemoney/providers/healthCheck";
import { privacyRoutes } from "./routes/privacy";
import { developerDashboardRoutes } from "./routes/developerDashboard";
import { travelRuleRoutes } from "./routes/travelRule";
import mtnCallbacksRouter from "./routes/mtnCallbacks";
import airtelCallbacksRouter from "./routes/airtelCallbacks";
import orangeCallbacksRouter from "./routes/orangeCallbacks";
import analyticsRouter from "./routes/analytics";
import sep31Router from "./stellar/sep31";
import sep24Router from "./stellar/sep24";
import sep38Router from "./stellar/sep38";
import { createSep12Router } from "./stellar/sep12";
import { createSep10Router } from "./stellar/sep10";
import { sep30Routes } from "./routes/sep30";
import { createAdminSep10Router } from "./stellar/adminSep10";
import tomlRouter from "./routes/toml";
import feeStrategiesRouter from "./routes/feeStrategies";
import feeRoutingRouter from "./routes/feeRouting";
import crossChainRouter from "./routes/crossChain";
import stellarRouter from "./routes/stellar";
import reconciliationRoutes from "./routes/reconciliation";
import accountingReconciliationRoutes from "./routes/accountingReconciliation";
import exchangeRateBufferRoutes from "./routes/exchangeRateBuffers";
import adminAssetRoutes from "./routes/admin/assets";
import settingsRoutes from "./routes/settings";
import { requestLogger } from "./middleware/logger";
import { statementsRoutes } from "./routes/statements";
import subscriptionsRoutes from "./routes/subscriptions";
import { paymentLinkRoutes } from "./routes/paymentLinkRoutes.js";
import providerStatusRouter from "./routes/providerStatus";
import providerHealthRouter from "./routes/providerHealthRoutes";
import kycWebhookRouter from "./routes/kycWebhookRoutes";
import twoFactorRouter from "./routes/twoFactorRoutes";
import { transactionMetadataRouter } from "./routes/transactionMetadataRoutes";
import transactionFilterRouter from "./routes/transactionFilters";
import notificationHealthRouter from "./routes/notificationHealth";
import complianceTrainingRouter from "./routes/complianceTraining";
import healthProvidersRouter from "./routes/healthProviders";
import adminReplicasRouter from "./routes/adminReplicas";
import connectionDashboardRouter from "./routes/connectionDashboard";
import maintenanceRoutes from "./routes/maintenanceRoutes";
import { transactionStreamRoutes } from "./routes/stream";
import { batchOperationRoutes } from "./routes/batchOperations";
import providerThrottleAdminRouter from "./routes/providerThrottleAdmin";
import {
  startHeartbeatService,
  stopHeartbeatService,
} from "./services/heartbeatService";
import { startStellarExporter } from "./services/stellarExporter";
import { slidingWindowRateLimit } from "./middleware/slidingWindowRateLimit";

// Sentry Middleware
import { initSentry, sentryBreadcrumbMiddleware } from "./middleware/sentry";
import { WebSocketManager } from "./websocket";
import { layeredCache } from "./services/layeredCache";
import { ERROR_CODES } from "./constants/errorCodes";
import { startApolloServer } from "./graphql/server";
import { RequestTracker } from "./utils/requestTracker";

dotenv.config();

if (process.env.SENTRY_DSN) {
  initSentry(process.env.SENTRY_DSN, process.env.SENTRY_RELEASE);
}

validateStellarNetwork();
logStellarNetwork();

const app = express();
const PORT = process.env.PORT || 3000;
const SHUTDOWN_TIMEOUT_MS = parseInt(
  process.env.SHUTDOWN_TIMEOUT_MS || "30000",
);

let server: Server | null = null;
let isShuttingDown = false;
let shutdownInProgress = false;
const requestTracker = new RequestTracker();

// Track every accepted request before parsing or application middleware runs so
// shutdown cannot close dependencies while a request is still being handled.
app.use((req: Request, res: Response, next: NextFunction) => {
  if (isShuttingDown) {
    res.setHeader("Connection", "close");
    throw createError(ERROR_CODES.SERVICE_UNAVAILABLE, "Service Unavailable", {
      error: "Service Unavailable",
      message: "Server is shutting down. Please retry shortly.",
    });
  }

  const releaseRequest = requestTracker.start();
  res.once("finish", releaseRequest);
  res.once("close", releaseRequest);
  next();
});

if (process.env.SENTRY_DSN) {
  Sentry.setupExpressErrorHandler(app);
}

app.use(sentryBreadcrumbMiddleware);

app.use(rateLimitMiddleware);

app.use(metricsMiddleware);
app.use(helmet());

// Compression middleware
if (process.env.COMPRESSION_ENABLED !== "false") {
  app.use(
    compression({
      threshold: parseInt(process.env.COMPRESSION_THRESHOLD || "1024"),
      level: parseInt(process.env.COMPRESSION_LEVEL || "6"),
      filter: (req, res) => {
        if (req.headers["x-no-compression"]) {
          return false;
        }
        // Don't compress already compressed content types
        const contentType = res.getHeader("content-type") as string;
        if (
          contentType &&
          (contentType.includes("image/") ||
            contentType.includes("video/") ||
            contentType.includes("audio/") ||
            contentType.includes("application/zip") ||
            contentType.includes("application/gzip"))
        ) {
          return false;
        }
        return compression.filter(req, res);
      },
    }),
  );
}

app.use(
  express.json({
    limit: process.env.REQUEST_SIZE_LIMIT || "10mb",
    verify: (req: IncomingMessage, _res, buf) => {
      (req as IncomingMessage & { rawBody?: Buffer }).rawBody = buf;
    },
  }),
);
app.use(
  express.urlencoded({
    limit: process.env.REQUEST_SIZE_LIMIT || "10mb",
    extended: true,
  }),
);
app.use(rateLimitDefaultMiddleware);
app.use(responseTime);
app.use(requestId);
app.use(requestLogger);
app.use(readReplicaRoutingMiddleware);
app.use(i18nMiddleware);
app.use(dbConnectionLeakDetector);

const sessionSecret =
  process.env.SESSION_SECRET || "default-secret-change-in-production";
const redisStore = createRedisStore();

app.use(
  session(<SessionOptions>{
    store: redisStore,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: SESSION_TTL_SECONDS * 1000,
    },
  }),
);
app.use(sessionAnomalyLogger);

/**
 * Get aggregated provider health summary
 */
async function getProviderHealthSummary(): Promise<ProviderHealthSummary> {
  try {
    const healthResult = await checkMobileMoneyHealth();
    const providers = healthResult.providers;
    const providerNames = Object.keys(providers) as ProviderName[];

    const providerStatus: Record<string, "up" | "down" | "unknown"> = {};
    let healthyCount = 0;

    for (const name of providerNames) {
      const status = providers[name]?.status ?? "unknown";
      providerStatus[name] = status;
      if (status === "up") healthyCount++;
    }

    const totalCount = providerNames.length;
    let overall: "healthy" | "degraded" | "down";

    if (healthyCount === totalCount) {
      overall = "healthy";
    } else if (healthyCount > 0) {
      overall = "degraded";
    } else {
      overall = "down";
    }

    return {
      overall,
      providers: providerStatus,
      healthyCount,
      totalCount,
    };
  } catch (err) {
    console.error("Provider health check failed", err);
    return {
      overall: "unknown",
      providers: {},
      healthyCount: 0,
      totalCount: 0,
    };
  }
}

app.get("/health", async (_req: Request, res: Response) => {
  const providerHealth = await getProviderHealthSummary();
  const body: HealthCheckResponse = {
    status: "ok",
    timestamp: new Date().toISOString(),
    gitHash: process.env.BUILD_HASH,
    providers: providerHealth,
  };
  res.json(body);
});

app.get("/ready", async (_req: Request, res: Response) => {
  const checks: Record<string, string> = {
    database: "down",
    redis: "down",
    shutdown: isShuttingDown ? "in-progress" : "idle",
  };
  let allReady = true;

  if (isShuttingDown) {
    allReady = false;
  }

  try {
    await pool.query("SELECT 1");
    checks.database = "ok";
  } catch (err) {
    console.error("Database check failed", err);
    allReady = false;
  }

  try {
    if (redisClient?.isOpen) {
      await redisClient.ping();
      checks.redis = "ok";
    } else {
      checks.redis = "closed";
      allReady = false;
    }
  } catch (err) {
    console.error("Redis check failed", err);
    allReady = false;
  }

  // Replication status is informational: a lagging or down replica degrades
  // the replication check but reads fall back to the primary, so it does not
  // flip the pod to not-ready (that would defeat DR redundancy).
  try {
    const replication = await getReplicationStatus();
    checks.replication = replication.status;
    checks.dr_mode = replication.drMode;
  } catch (err) {
    console.error("Replication check failed", err);
    checks.replication = "unknown";
    checks.dr_mode = "standby";
  }

  const body: ReadinessCheckResponse = {
    status: allReady ? "ready" : "not ready",
    checks,
    timestamp: new Date().toISOString(),
  };
  res.status(allReady ? 200 : 503).json(body);
});

app.get("/admin/dashboard", (_req: Request, res: Response) => {
  res.sendFile(path.join(process.cwd(), "public", "admin-dashboard.html"));
});

// Load Balancer Health Check
let lbHealthCache: { data: any; timestamp: number } | null = null;
const LB_HEALTH_CACHE_TTL = 5000;

app.get("/health/lb", async (req: Request, res: Response) => {
  const now = Date.now();
  if (lbHealthCache && now - lbHealthCache.timestamp < LB_HEALTH_CACHE_TTL) {
    res
      .status(lbHealthCache.data.status === "ok" ? 200 : 503)
      .json(lbHealthCache.data);
    return;
  }

  const checks: Record<string, string> = {
    database: "down",
    redis: "down",
    memory: "ok",
  };
  let healthy = true;

  if (isShuttingDown) {
    healthy = false;
  }

  try {
    await pool.query("SELECT 1");
    checks.database = "ok";
  } catch (err) {
    healthy = false;
  }

  try {
    if (redisClient?.isOpen) {
      await redisClient.ping();
      checks.redis = "ok";
    } else {
      checks.redis = "closed";
      healthy = false;
    }
  } catch (err) {
    healthy = false;
  }

  // Check provider health
  try {
    const providerHealth = await getProviderHealthSummary();
    checks.providers = providerHealth.overall;
    if (providerHealth.overall === "down") {
      healthy = false;
    } else if (providerHealth.overall === "degraded") {
      // Don't mark as unhealthy, but track it
      checks.providersDetail = JSON.stringify(providerHealth.providers);
    }
  } catch (err) {
    console.error("Provider health check failed", err);
    checks.providers = "error";
  }

  const memUsage = process.memoryUsage();
  if (memUsage.heapUsed > 1024 * 1024 * 1024) {
    // 1GB limit
    checks.memory = "high";
    healthy = false;
  }

  const responseData = {
    status: healthy ? "ok" : "error",
    checks,
    timestamp: new Date().toISOString(),
  };

  lbHealthCache = { data: responseData, timestamp: now };
  res.status(healthy ? 200 : 503).json(responseData);
});

app.use(globalTimeout);
app.use(haltOnTimedout);

app.use(apiVersionMiddleware);
app.use(validateVersionMiddleware);
// #393 – Add Deprecation / Sunset / Link headers to registered legacy endpoints
app.use(deprecationMiddleware);
app.use("/oauth", createOAuthRouter());

// #480 – Advanced transaction filtering (saved filter templates, filter AST).
// Mounted *before* the version-negotiated transaction router on purpose: that
// router serves GET /:id, which would otherwise capture
// GET /api/transactions/filters and answer "transaction not found".
app.use("/api/transactions/filters", transactionFilterRouter);

// Replay retried mutations instead of processing them twice (Idempotency-Key)
app.use("/api/v1/transactions", idempotency());
app.use("/api/transactions", idempotency());
app.use("/api/bulk", idempotency());

app.use("/api/v1/transactions", transactionRoutesV1);
app.use("/api/v1/transactions", transactionDisputeRoutesV1);
app.use("/api/v1/transactions/bulk", bulkRoutesV1);
app.use("/api/v1/disputes", disputeRoutesV1);
app.use("/api/v1/stats", statsRoutesV1);
app.use("/api/v1/vaults", vaultRoutesV1);
app.use("/api/v1/compliance/travel-rule", travelRuleRoutes);
app.use("/api/compliance", complianceVersionsRouter);
app.use("/api/v2/transactions", transactionRoutesV2);
app.use("/api/stream", transactionStreamRoutes);

app.use("/api/transactions", (req: VersionedRequest, res, next) => {
  // Route by the negotiated version (URL path takes priority in
  // apiVersionMiddleware; falls back to Accept-Version/Accept headers).
  if (req.apiVersion === "v2") {
    return transactionRoutesV2(req, res, next);
  }

  req.apiVersion = "v1";
  res.setHeader("API-Version", "v1");
  res.setHeader("Deprecation", "true");
  res.setHeader(
    "Sunset",
    new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toUTCString(),
  );
  res.setHeader(
    "Url",
    `https://example.com${req.originalUrl.replace("/api/", "/api/v1/")}`,
  );
  return transactionRoutes(req, res, next);
});
app.use("/api/transactions", transactionDisputeRoutes);
app.use("/api/transactions/bulk", bulkRoutes);
// Alias so bulk operations can be polled at /api/bulk/:jobId/status
app.use("/api/bulk", bulkRoutes);
app.use("/api/disputes", disputeRoutes);
app.use("/api/stats", statsRoutes);
app.use("/api/contacts", contactsRoutes);
app.use("/api/mtn", mtnCallbacksRouter);
app.use("/api/airtel", airtelCallbacksRouter);
app.use("/api/orange", orangeCallbacksRouter);
app.use("/api/reports", reportsRoutes);
app.use("/api/fees", feesRoutes);
app.use("/api/users", userRoutes);
app.use("/api/kyc", createKYCRoutes(pool));
// Split payments
app.use("/api/split-payments", splitPaymentRulesRouter);
app.use("/api/transactions", splitPaymentTransactionRouter);
app.use("/api/fee-strategies", feeStrategiesRouter);
app.use("/api/fee-routing", feeRoutingRouter);
app.use("/api/cross-chain", crossChainRouter);
app.use("/api/stellar", stellarRouter);
app.use("/api/reconciliation", reconciliationRoutes);
app.use("/api/exchange-rate-buffers", exchangeRateBufferRoutes);
app.use("/api/admin/assets", adminAssetRoutes);
app.use("/api/settings", settingsRoutes);
app.use("/api/preferences", settingsRoutes);
app.use("/api/statements", statementsRoutes);
app.use("/api/subscriptions", subscriptionsRoutes);
app.use("/api/invoices", invoiceRoutes);
app.use("/", paymentLinkRoutes);

// GDPR
app.use("/api/gdpr", privacyRoutes);
app.use("/api/developer", developerDashboardRoutes);
app.use("/api/admin", requireAuth, adminRoutes);
// #573 – webhook circuit breaker state and manual reset. The router applies
// requireAuth and requireAdmin itself, since it is also useful on its own.
app.use("/api/admin/webhooks", webhookCircuitBreakerRoutes);
app.use("/api/admin/providers/status", requireAuth, providerStatusRouter);
// #405 – Provider Health Dashboard
app.use("/api/admin/providers/health", requireAuth, providerHealthRouter);
// #393 – Deprecation timeline & usage monitoring
app.use("/api/admin/deprecations", requireAuth, adminDeprecationRoutes);
app.use("/api/admin/kyc-upgrades", requireAuth, kycTierUpgradeRoutes);
app.use("/api/admin/analytics", requireAuth, analyticsRouter);
app.use("/api/admin/auth", createAdminSep10Router());
// #402 – KYC Webhook Callbacks
app.use("/api/kyc/webhooks", kycWebhookRouter);
// #403 – Transaction Metadata Search
app.use("/api/transactions/metadata", transactionMetadataRouter);
// #479 – real-time notification system status
app.use("/api/notifications", notificationHealthRouter);
// #481 – compliance training dashboard, assignments and certifications
app.use("/api/compliance/training", complianceTrainingRouter);
// #404 – Fraud Detection Logging
app.use("/api/fraud", fraudRoutes);
// #404 – 2FA Multi-method
app.use("/api/auth/2fa", twoFactorRouter);
// #392 – Batch Import Status Tracking
app.use("/api/batch-operations", batchOperationRoutes);
// #625 – Provider Throttle Dead-Letter Queue admin API
app.use("/api/admin/provider-throttle", providerThrottleAdminRouter);
// #358 – Provider Health Aggregation
app.use("/api/health", healthProvidersRouter);
// #356 – Read Replica Health Admin
app.use("/api/admin/replicas", requireAuth, adminReplicasRouter);
// #355 – Connection Pool Dashboard
app.use("/api/admin/connections", requireAuth, connectionDashboardRouter);
// #482/#484/#483/#485 – Automatic database optimization, provider contract
// version management, transaction reversal audit and ML fraud detection
app.use("/api/admin/maintenance", requireAuth, maintenanceRoutes);
app.use("/api/receipt-templates", receiptTemplateRoutes);
app.use("/sep10", createSep10Router());
app.use("/sep31", sep31Router);
app.use("/sep24", sep24Router);
app.use("/sep38", sep38Router);
app.use("/sep12", createSep12Router(pool));
app.use("/sep30", sep30Routes);
app.use("/.well-known/stellar.toml", tomlRouter);

// Prometheus Metrics Scraper Endpoint
app.get("/metrics", async (req: Request, res: Response) => {
  try {
    res.set("Content-Type", register.contentType);
    res.end(await register.metrics());
  } catch (ex) {
    res.status(500).end(String(ex));
  }
});

app.use(
  (
    err: Error & { type?: string },
    _req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    if (err.type === "entity.too.large") {
      throw createError(ERROR_CODES.LIMIT_EXCEEDED, "Payload Too Large", {
        error: "Payload Too Large",
        message: `Request exceeds the maximum size of ${process.env.REQUEST_SIZE_LIMIT || "10mb"}`,
      });
    }

    next(err);
  },
);

if (process.env.SENTRY_DSN) {
  app.use(Sentry.expressErrorHandler());
}

app.use(timeoutErrorHandler);
app.use(errorHandler);

async function gracefulShutdown(signal: NodeJS.Signals): Promise<void> {
  if (shutdownInProgress) {
    console.log(`[Shutdown] ${signal} received; shutdown already in progress`);
    return;
  }

  shutdownInProgress = true;
  isShuttingDown = true;
  console.log(`[Shutdown] Received ${signal}. Starting graceful shutdown...`);

  try {
    if (server) {
      console.log(
        "[Shutdown] Stopping HTTP server from accepting new requests",
      );
      // Initiate listener closure before cleaning up dependencies so no new
      // work can enter while the existing requests drain.
      server.close((error) => {
        if (
          error &&
          (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING"
        ) {
          console.error("[Shutdown] HTTP listener close failed", error);
          return;
        }
        console.log("[Shutdown] HTTP listener closed");
      });
    }

    if (wsManager) {
      console.log("[Shutdown] Closing WebSocket connections");
      await wsManager.close();
      wsManager = null;
      console.log("[Shutdown] WebSocket connections closed");
    }

    const pendingAtStart = requestTracker.activeCount;
    if (pendingAtStart > 0) {
      console.log(
        `[Shutdown] Waiting for ${pendingAtStart} active request(s) to finish (timeout ${SHUTDOWN_TIMEOUT_MS}ms)`,
      );
    }

    await requestTracker.waitForZero(SHUTDOWN_TIMEOUT_MS);

    if (requestTracker.activeCount > 0) {
      console.warn(
        `[Shutdown] Timed out waiting for active requests. Remaining: ${requestTracker.activeCount}`,
      );
      server?.closeAllConnections?.();
    } else {
      console.log("[Shutdown] All active requests finished");
    }

    console.log("[Shutdown] Draining queue resources");
    const { shutdownQueue } = await import("./queue/index.js");
    await shutdownQueue();
    console.log("[Shutdown] Queue resources closed");

    console.log("[Shutdown] Stopping heartbeat service");
    stopHeartbeatService();
    console.log("[Shutdown] Heartbeat service stopped");

    console.log("[Shutdown] Closing PostgreSQL pool");
    await pool.end();
    console.log("[Shutdown] PostgreSQL pool closed");

    console.log("[Shutdown] Closing Redis client");
    await disconnectRedis();
    console.log("[Shutdown] Redis client closed");

    console.log("[Shutdown] Closing WebSocket servers");
    if (wsManager) {
      await wsManager.close();
      wsManager = null;
    }
    if (graphqlServerCleanup) {
      await graphqlServerCleanup.dispose();
      graphqlServerCleanup = null;
    }
    console.log("[Shutdown] WebSocket servers closed");

    console.log("[Shutdown] Graceful shutdown complete");
    process.exit(0);
  } catch (error) {
    console.error("[Shutdown] Shutdown sequence failed", error);
    process.exit(1);
  }
}

process.once("SIGTERM", () => {
  void gracefulShutdown("SIGTERM");
});

process.once("SIGINT", () => {
  void gracefulShutdown("SIGINT");
});

export let wsManager: WebSocketManager | null = null;
let graphqlServerCleanup: ServerCleanup | null = null;

async function initializeRuntime(): Promise<void> {
  if (process.env.NODE_ENV === "test") {
    return;
  }

  // #393 – Populate the deprecation registry with legacy endpoint notices.
  seedDeprecations();

  // Initialize background jobs and monitoring
  const { startJobs } = await import("./jobs/scheduler.js");
  startJobs();

  // #356 – Start replica health monitoring loop
  const { startReplicaHealthMonitoring } = await import("./middleware/readReplicaRouting.js");
  startReplicaHealthMonitoring();

  // #355 – Start long-running transaction monitor
  const { startLongRunningTransactionMonitor } = await import("./middleware/transactionLeakDetector.js");
  startLongRunningTransactionMonitor();

  // Initialize Prometheus Horizon Scraper
  startStellarExporter();

  // Initialize System Heartbeat Metric
  startHeartbeatService();

  const { getQueueHealth, pauseQueueEndpoint, resumeQueueEndpoint } =
    await import("./queue/health.js");
  const { queueDepthHandler, queueDepthPrometheusHandler } =
    await import("./queue/queueDepthMetrics.js");
  const { startQueueMetricsCollection, stopQueueMetricsCollection } =
    await import("./queue/index.js");

  app.get("/health/queue", getQueueHealth);
  app.get("/health/queue/depth", queueDepthHandler);
  app.get("/metrics/queue_depth", queueDepthPrometheusHandler);
  app.post("/admin/queues/pause", pauseQueueEndpoint);
  app.post("/admin/queues/resume", resumeQueueEndpoint);

  startQueueMetricsCollection();

  try {
    await connectRedis();
    console.log("Redis initialized");

    await layeredCache.init();
    console.log("Layered cache (L1/L2) initialized");

    const { providerSettingsService } =
      await import("./services/providerSettingsService.js");
    await providerSettingsService.getAllSettings();
    console.log("Provider settings cache initialized");

    const {
      startProviderBalanceAlertWorker,
      scheduleProviderBalanceAlertJob,
      startAccountingTokenRefreshWorker,
    } = await import("./queue/index.js");
    startProviderBalanceAlertWorker();
    startAccountingTokenRefreshWorker();
    await scheduleProviderBalanceAlertJob();
    console.log("Provider balance alert queue initialized");
  } catch (err) {
    console.error("Redis failed", err);
    console.warn("Distributed locks not available");
  }

  const { createQueueDashboard } = await import("./queue/dashboard.js");
  app.use("/admin/queues", createQueueDashboard());

  //
  const useHTTP2 = process.env.USE_HTTP2 === "true";

  if (useHTTP2) {
    const sslOptions = {
      key: fs.readFileSync(path.join(__dirname, "../certs/key.pem")),
      cert: fs.readFileSync(path.join(__dirname, "../certs/cert.pem")),
    };

    const http2Server = spdy.createServer(sslOptions, app);
    http2Server.listen(PORT, () => {
      console.log(`HTTP/2 server running on https://localhost:${PORT}`);
    });
    server = http2Server as unknown as Server;
  } else {
    server = app.listen(PORT, () => {
      console.log(`HTTP/1.1 server running on http://localhost:${PORT}`);
    });

    wsManager = new WebSocketManager(server, {
      // Issue #814: revalidate credentials and account status at handshake
      // time (stateful Redis check + frozen/suspended/deactivated rejection).
      verifyConnection: async (token) => {
        const claims = await verifyTokenStateful(token);
        if (claims.userId && !(await isAccountActive(claims.userId))) {
          throw new Error("Account is not active");
        }
        return claims;
      },
    });
    console.log("WebSocket server attached");

    // Start Apollo Server with APQ enabled (must run after HTTP server is created)
    graphqlServerCleanup = await startApolloServer(app, server);
    console.log("Apollo GraphQL server started at /graphql");
  }
}

if (process.env.NODE_ENV !== "test") {
  void initializeRuntime();
}

export default app;
