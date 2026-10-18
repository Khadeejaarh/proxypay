/**
 * Advanced Dispute Routes
 *
 * Enhanced endpoints with evidence attachments, internal notes, and SLA management:
 *
 *   POST   /api/transactions/:id/dispute
 *     Open a dispute for a transaction.
 *     Body: { reason: string, reportedBy?: string, priority?: string, category?: string }
 *
 *   GET    /api/disputes/:disputeId
 *     Fetch dispute details including all notes.
 *
 *   GET    /api/disputes/:disputeId/details
 *     Fetch dispute with full details (notes, evidence, timeline).
 *
 *   GET    /api/disputes/:disputeId/notes
 *     Cursor-paginated notes (limit?, cursor?, sort?: date|relevance).
 *
 *   PATCH  /api/disputes/:disputeId/status
 *     Transition dispute status.
 *     Body: { status: 'open'|'investigating'|'resolved'|'rejected'|'reversed'|'upheld', resolution?: string, assignedTo?: string }
 *
 *   POST   /api/disputes/:disputeId/resolve
 *     Admin reverses or upholds a disputed payment.
 *     Body: { action: 'reverse'|'uphold', resolution: string, adminId?: string }
 *
 *   PATCH  /api/disputes/:disputeId
 *     Update dispute fields.
 *     Body: { priority?: string, category?: string, internalNotes?: string }
 *
 *   POST   /api/disputes/:disputeId/assign
 *     Assign dispute to a support agent (auto-advances open → investigating).
 *     Body: { agentName: string }
 *
 *   POST   /api/disputes/:disputeId/notes
 *     Add a note/comment to a dispute.
 *     Body: { author: string, note: string }
 *
 *   POST   /api/disputes/:disputeId/evidence
 *     Upload evidence attachment.
 *     Form data: file (multipart), description (optional)
 *
 *   POST   /api/disputes/:disputeId/evidence/multiple
 *     Upload multiple evidence attachments.
 *     Form data: files[] (multipart), descriptions[] (optional)
 *
 *   GET    /api/disputes/:disputeId/evidence
 *     Get all evidence for a dispute.
 *
 *   GET    /api/disputes/report
 *     Aggregate dispute report.
 *     Query: from?, to?, assignedTo?
 *
 *   GET    /api/disputes/sla/report
 *     SLA compliance report.
 *     Query: days? (default: 30)
 *
 *   GET    /api/disputes/overdue
 *     Get overdue disputes.
 *
 *   POST   /api/disputes/sla/process
 *     Manually trigger SLA warning processing.
 */

import { Router, Request, Response } from "express";
import { DisputeService } from "../services/dispute";
import { DisputeTimelineService } from "../services/disputeTimeline";
import { DisputeStatus, DisputePriority } from "../models/dispute";
import { DisputeStateMachine } from "../services/disputeStateMachine";
import {
  uploadSingle,
  uploadMultiple,
  handleDisputeUploadError,
} from "../middleware/disputeUpload";
import { DISPUTE_EVIDENCE_UPLOAD_LIMITS } from "../config/uploadLimits";
import {
  uploadDisputeEvidenceToS3,
  uploadMultipleDisputeEvidenceToS3,
  validateDisputeEvidenceFile,
} from "../services/disputeS3Upload";
import {
  generateDisputeSlaReport,
  runDisputeSlaJob,
} from "../jobs/disputeSlaJob";
import { requireAuth } from "../middleware/auth";
import { requirePermission } from "../middleware/rbac";
import { createError } from "../middleware/errorHandler";
import { ERROR_CODES } from "../constants/errorCodes";
import { PaginationError } from "../utils/pagination";
import {
  gateUpload,
  linkStoredKey,
  UploadGateResult,
} from "../services/fileSecurityService";

const VALID_STATUSES: DisputeStatus[] = [
  "open",
  "investigating",
  "resolved",
  "rejected",
  "reversed",
  "upheld",
];

const VALID_PRIORITIES: DisputePriority[] = [
  "low",
  "medium",
  "high",
  "critical",
];

const disputeService = new DisputeService();
const stateMachine = new DisputeStateMachine();
const timelineService = new DisputeTimelineService();

// ---------------------------------------------------------------------------
// Transaction-scoped router  (mounted at /api/transactions)
// ---------------------------------------------------------------------------

export const transactionDisputeRoutes = Router({ mergeParams: true });

/**
 * POST /api/transactions/:id/dispute
 *
 * Opens a dispute for a transaction and automatically creates a support ticket
 * (Zendesk/Intercom) with full transaction context.
 *
 * Body: {
 *   reason: string,
 *   reportedBy?: string,
 *   priority?: string,
 *   category?: string,
 *   requesterEmail?: string  // Email for support ticket requester
 * }
 *
 * Response includes:
 *   - supportTicketId: Instant ticket ID from support provider
 *   - supportTicketUrl: Direct link to the support ticket
 */
transactionDisputeRoutes.post(
  "/:id/dispute",
  requireAuth,
  requirePermission("dispute:create"),
  async (req: Request, res: Response) => {
    const { id } = req.params;
    const { reason, reportedBy, priority, category, requesterEmail } = req.body;

    if (!reason || typeof reason !== "string" || reason.trim().length === 0) {
      throw createError(
        ERROR_CODES.MISSING_FIELD,
        'Field "reason" is required and must be a non-empty string',
        { error: 'Field "reason" is required and must be a non-empty string' },
      );
    }

    if (priority && !VALID_PRIORITIES.includes(priority)) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        `Invalid priority. Must be one of: ${VALID_PRIORITIES.join(", ")}`,
        {
          error: `Invalid priority. Must be one of: ${VALID_PRIORITIES.join(", ")}`,
        },
      );
    }

    // Validate requesterEmail if provided
    if (requesterEmail && typeof requesterEmail === "string") {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(requesterEmail)) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          'Invalid "requesterEmail" format',
          {
            error: 'Invalid "requesterEmail" format',
          },
        );
      }
    }

    try {
      const dispute = await disputeService.openDispute(
        id,
        reason.trim(),
        reportedBy,
        priority,
        category,
      );
      return res.status(201).json(dispute);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to open dispute";
      const status = message.includes("not found")
        ? ERROR_CODES.NOT_FOUND
        : message.includes("already exists")
          ? ERROR_CODES.CONFLICT
          : message.includes("only allowed for completed")
            ? ERROR_CODES.CONFLICT
            : ERROR_CODES.INTERNAL_ERROR;
      throw createError(status, message, { error: message });
    }
  },
);

// ---------------------------------------------------------------------------
// Dispute management router  (mounted at /api/disputes)
// ---------------------------------------------------------------------------

export const disputeRoutes = Router();

/**
 * GET /api/disputes/report
 * Must be defined before /:disputeId so "report" is not treated as an ID.
 */
disputeRoutes.get(
  "/report",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    const { from, to, assignedTo } = req.query;

    const filter: { from?: Date; to?: Date; assignedTo?: string } = {};

    if (from) {
      const d = new Date(from as string);
      if (isNaN(d.getTime()))
        throw createError(ERROR_CODES.INVALID_INPUT, 'Invalid "from" date', {
          error: 'Invalid "from" date',
        });
      filter.from = d;
    }
    if (to) {
      const d = new Date(to as string);
      if (isNaN(d.getTime()))
        throw createError(ERROR_CODES.INVALID_INPUT, 'Invalid "to" date', {
          error: 'Invalid "to" date',
        });
      filter.to = d;
    }
    if (assignedTo) filter.assignedTo = assignedTo as string;

    try {
      const report = await disputeService.generateReport(filter);
      return res.json(report);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to generate report";
      throw createError(ERROR_CODES.INTERNAL_ERROR, message, {
        error: message,
      });
    }
  },
);

/**
 * GET /api/disputes/sla/report
 */
disputeRoutes.get(
  "/sla/report",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    const days = req.query.days ? parseInt(req.query.days as string, 10) : 30;

    if (isNaN(days) || days < 1 || days > 365) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "Invalid days parameter. Must be between 1 and 365",
        {
          error: "Invalid days parameter. Must be between 1 and 365",
        },
      );
    }

    try {
      const report = await generateDisputeSlaReport(days);
      return res.json(report);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to generate SLA report";
      throw createError(ERROR_CODES.INTERNAL_ERROR, message, {
        error: message,
      });
    }
  },
);

/**
 * GET /api/disputes/overdue
 */
disputeRoutes.get(
  "/overdue",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    try {
      const overdue = await disputeService.getOverdueDisputes();
      return res.json(overdue);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to get overdue disputes";
      // return res.status(500).json({ error: message });
      throw createError(ERROR_CODES.INTERNAL_ERROR, message, {
        error: message,
      });
    }
  },
);

/**
 * POST /api/disputes/sla/process
 */
disputeRoutes.post(
  "/sla/process",
  requireAuth,
  requirePermission("dispute:manage"),
  async (req: Request, res: Response) => {
    try {
      const result = await runDisputeSlaJob();
      return res.json(result);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to process SLA warnings";
      throw createError(ERROR_CODES.INTERNAL_ERROR, message, {
        error: message,
      });
    }
  },
);

/**
 * POST /api/disputes/:disputeId/resolve
 */
disputeRoutes.post(
  "/:disputeId/resolve",
  requireAuth,
  requirePermission("dispute:manage"),
  async (req: Request, res: Response) => {
    const { action, resolution, adminId } = req.body;

    if (action !== "reverse" && action !== "uphold") {
      return res.status(400).json({
        error: 'Field "action" must be one of: reverse, uphold',
      });
    }

    if (
      !resolution ||
      typeof resolution !== "string" ||
      resolution.trim().length === 0
    ) {
      return res.status(400).json({
        error: 'Field "resolution" is required and must be a non-empty string',
      });
    }

    try {
      const updated = await disputeService.resolvePayment(
        req.params.disputeId,
        action,
        resolution,
        adminId ?? req.user?.id,
      );
      return res.json(updated);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to resolve dispute";
      const code = message.includes("not found")
        ? 404
        : message.includes("Cannot resolve") ||
            message.includes("Resolution text")
          ? 422
          : 500;
      return res.status(code).json({ error: message });
    }
  },
);

/**
 * GET /api/disputes/:disputeId/timeline
 *
 * Returns the enriched, phase-grouped timeline for a dispute.
 *
 * Response: {
 *   disputeId: string,
 *   totalEvents: number,
 *   phases: Array<{ phase, label, events[] }>,
 *   events: EnrichedTimelineEvent[]
 * }
 */
disputeRoutes.get(
  "/:disputeId/timeline",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    try {
      const timeline = await timelineService.getTimeline(req.params.disputeId);
      return res.json(timeline);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to get timeline";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        { error: message },
      );
    }
  },
);

/**
 * POST /api/disputes/:disputeId/timeline
 *
 * Manually add a timeline event (e.g. a note, admin action, or custom event).
 *
 * Body: {
 *   eventType: string,          // e.g. 'manual_note', 'comment'
 *   actor: string,              // who triggered it
 *   description?: string,
 *   oldStatus?: string,
 *   newStatus?: string,
 *   metadata?: object
 * }
 *
 * Response: EnrichedTimelineEvent (201)
 */
disputeRoutes.post(
  "/:disputeId/timeline",
  requireAuth,
  requirePermission("dispute:update"),
  async (req: Request, res: Response) => {
    const { eventType, actor, description, oldStatus, newStatus, metadata } =
      req.body;

    if (
      !eventType ||
      typeof eventType !== "string" ||
      eventType.trim().length === 0
    ) {
      throw createError(
        ERROR_CODES.MISSING_FIELD,
        'Field "eventType" is required and must be a non-empty string',
        {
          error: 'Field "eventType" is required and must be a non-empty string',
        },
      );
    }

    if (!actor || typeof actor !== "string" || actor.trim().length === 0) {
      throw createError(
        ERROR_CODES.MISSING_FIELD,
        'Field "actor" is required and must be a non-empty string',
        { error: 'Field "actor" is required and must be a non-empty string' },
      );
    }

    if (metadata !== undefined && (typeof metadata !== "object" || Array.isArray(metadata))) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        'Field "metadata" must be a plain object if provided',
        { error: 'Field "metadata" must be a plain object if provided' },
      );
    }

    try {
      const event = await timelineService.addEvent(
        req.params.disputeId,
        eventType.trim(),
        actor.trim(),
        description,
        oldStatus,
        newStatus,
        metadata,
      );
      return res.status(201).json(event);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to add timeline event";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        { error: message },
      );
    }
  },
);

/**
 * GET /api/disputes/:disputeId
 */
disputeRoutes.get(
  "/:disputeId",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    try {
      const dispute = await disputeService.getDispute(req.params.disputeId);
      return res.json(dispute);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to fetch dispute";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        {
          error: message,
        },
      );
    }
  },
);

/**
 * GET /api/disputes/:disputeId/details
 */
disputeRoutes.get(
  "/:disputeId/details",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    try {
      const dispute = await disputeService.getDisputeWithDetails(
        req.params.disputeId,
      );
      return res.json(dispute);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to fetch dispute details";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        {
          error: message,
        },
      );
    }
  },
);

/**
 * PATCH /api/disputes/:disputeId/status
 */
disputeRoutes.patch(
  "/:disputeId/status",
  requireAuth,
  requirePermission("dispute:update"),
  async (req: Request, res: Response) => {
    const { status, resolution, assignedTo } = req.body;

    if (!status || !VALID_STATUSES.includes(status)) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        `Field "status" must be one of: ${VALID_STATUSES.join(", ")}`,
        {
          error: `Field "status" must be one of: ${VALID_STATUSES.join(", ")}`,
        },
      );
    }

    try {
      // Get current dispute to validate transition
      const currentDispute = await disputeService.getDispute(
        req.params.disputeId,
      );

      // Validate state transition
      const validation = stateMachine.validateTransition(
        currentDispute.status,
        status,
        { resolution, assignedTo },
      );

      if (!validation.valid) {
        // return res.status(422).json({
        //   error: "Invalid state transition",
        //   details: validation.errors,
        // });
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          "Invalid state transition",
          {
            error: "Invalid state transition",
            details: validation.errors,
          },
        );
      }

      const updated = await disputeService.updateStatus(
        req.params.disputeId,
        status as DisputeStatus,
        resolution,
        assignedTo,
      );
      return res.json(updated);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to update dispute status";
      const code = message.includes("not found")
        ? ERROR_CODES.NOT_FOUND
        : message.includes("Cannot transition") ||
            message.includes("resolution text")
          ? ERROR_CODES.UNPROCESSABLE_CONTENT
          : ERROR_CODES.INTERNAL_ERROR;
      throw createError(code, message, {
        error: message,
      });
    }
  },
);

/**
 * PATCH /api/disputes/:disputeId
 */
disputeRoutes.patch(
  "/:disputeId",
  requireAuth,
  requirePermission("dispute:update"),
  async (req: Request, res: Response) => {
    const { priority, category, internalNotes } = req.body;

    if (priority && !VALID_PRIORITIES.includes(priority)) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        `Invalid priority. Must be one of: ${VALID_PRIORITIES.join(", ")}`,
        {
          error: `Invalid priority. Must be one of: ${VALID_PRIORITIES.join(", ")}`,
        },
      );
    }

    try {
      const updated = await disputeService.updateDispute(req.params.disputeId, {
        priority,
        category,
        internalNotes,
      });
      return res.json(updated);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to update dispute";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        {
          error: message,
        },
      );
    }
  },
);

/**
 * POST /api/disputes/:disputeId/assign
 */
disputeRoutes.post(
  "/:disputeId/assign",
  requireAuth,
  requirePermission("dispute:assign"),
  async (req: Request, res: Response) => {
    const { agentName } = req.body;

    if (
      !agentName ||
      typeof agentName !== "string" ||
      agentName.trim().length === 0
    ) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        'Field "agentName" is required',
        {
          error: 'Field "agentName" is required',
        },
      );
    }

    try {
      const updated = await disputeService.assignToAgent(
        req.params.disputeId,
        agentName.trim(),
      );
      return res.json(updated);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to assign dispute";
      const code = message.includes("not found")
        ? ERROR_CODES.NOT_FOUND
        : message.includes("Cannot assign")
          ? ERROR_CODES.UNPROCESSABLE_CONTENT
          : ERROR_CODES.INTERNAL_ERROR;
      throw createError(code, message, {
        error: message,
      });
    }
  },
);

/**
 * GET /api/disputes/:disputeId/notes
 *
 * Cursor-paginated notes for a dispute (issue #622). Large threads previously
 * had to be read off the dispute detail response, which loads every note.
 *
 * Query:
 *   limit?   page size, default 50 (max 100)
 *   cursor?  opaque cursor returned as `pagination.nextCursor`
 *   sort?    'date' (default, newest first) | 'relevance' (assigned agent first)
 */
disputeRoutes.get(
  "/:disputeId/notes",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    const { limit, cursor, sort } = req.query;

    if (sort !== undefined && sort !== "date" && sort !== "relevance") {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        'Query "sort" must be one of: date, relevance',
        { error: 'Query "sort" must be one of: date, relevance' },
      );
    }

    if (cursor !== undefined && typeof cursor !== "string") {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        'Query "cursor" must be a string',
        { error: 'Query "cursor" must be a string' },
      );
    }

    const parsedLimit =
      typeof limit === "string" ? parseInt(limit, 10) : undefined;
    if (
      limit !== undefined &&
      (parsedLimit === undefined ||
        !Number.isFinite(parsedLimit) ||
        parsedLimit < 1)
    ) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        'Query "limit" must be a positive integer',
        { error: 'Query "limit" must be a positive integer' },
      );
    }

    try {
      const page = await disputeService.getNotesPage(req.params.disputeId, {
        limit: parsedLimit,
        cursor: cursor as string | undefined,
        sort: (sort as "date" | "relevance" | undefined) ?? "date",
      });
      return res.json(page);
    } catch (error) {
      if (error instanceof PaginationError) {
        throw createError(ERROR_CODES.INVALID_INPUT, error.message, {
          error: error.message,
        });
      }

      const message =
        error instanceof Error
          ? error.message
          : "Failed to fetch dispute notes";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        {
          error: message,
        },
      );
    }
  },
);

/**
 * POST /api/disputes/:disputeId/notes
 */
disputeRoutes.post(
  "/:disputeId/notes",
  requireAuth,
  requirePermission("dispute:update"),
  async (req: Request, res: Response) => {
    const { author, note } = req.body;

    if (!author || typeof author !== "string" || author.trim().length === 0) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        'Field "author" is required',
        {
          error: 'Field "author" is required',
        },
      );
    }
    if (!note || typeof note !== "string" || note.trim().length === 0) {
      throw createError(ERROR_CODES.INVALID_INPUT, 'Field "note" is required', {
        error: 'Field "note" is required',
      });
    }

    try {
      const created = await disputeService.addNote(
        req.params.disputeId,
        author.trim(),
        note.trim(),
      );
      return res.status(201).json(created);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to add note";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        {
          error: message,
        },
      );
    }
  },
);

/**
 * POST /api/disputes/:disputeId/evidence
 */
disputeRoutes.post(
  "/:disputeId/evidence",
  requireAuth,
  requirePermission("dispute:update"),
  uploadSingle.single("file"),
  handleDisputeUploadError,
  async (req: Request, res: Response) => {
    const { disputeId } = req.params;
    const { description } = req.body;
    const file = req.file;

    if (!file) {
      throw createError(ERROR_CODES.INVALID_INPUT, "No file uploaded", {
        error: "No file uploaded",
      });
    }

    // Validate file
    const validation = validateDisputeEvidenceFile(file);
    if (!validation.valid) {
      throw createError(ERROR_CODES.INVALID_INPUT, validation.error, {
        error: validation.error,
      });
    }

    // Security scan: antivirus + magic-byte type validation + integrity hash.
    // The file must pass before anything is written to storage.
    const security = await gateUpload(file, {
      userId: req.user?.id || null,
    });
    if (security.outcome === "infected") {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "Upload rejected: file failed the security scan",
        { error: security.reason },
      );
    }
    if (security.outcome === "quarantined") {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        "Upload quarantined: scan engine unavailable, please retry later",
        { error: security.reason },
      );
    }
    if (security.outcome === "error" || !security.record) {
      throw createError(
        ERROR_CODES.INTERNAL_ERROR,
        "Upload security scan failed",
        { error: security.reason },
      );
    }

    try {
      // Upload to S3
      const uploadResult = await uploadDisputeEvidenceToS3({
        disputeId,
        file,
        uploadedBy: req.user?.id || "unknown",
      });

      if (!uploadResult.success) {
        throw createError(ERROR_CODES.INTERNAL_ERROR, uploadResult.error, {
          error: uploadResult.error,
        });
      }

      // Attach the stored key to the security record for integrity audits.
      if (uploadResult.success && uploadResult.key) {
        await linkStoredKey(security.record.id, uploadResult.key).catch(
          (err: unknown) => {
            console.error("Failed to link security record to S3 key:", err);
          },
        );
      }

      // Save evidence record
      const evidence = await disputeService.addEvidence(
        disputeId,
        file.originalname,
        file.mimetype,
        file.size,
        uploadResult.key!,
        uploadResult.fileUrl!,
        req.user?.id || "unknown",
        description,
      );

      return res.status(201).json(evidence);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to upload evidence";

      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        {
          error: message,
        },
      );
    }
  },
);

/**
 * POST /api/disputes/:disputeId/evidence/multiple
 */
disputeRoutes.post(
  "/:disputeId/evidence/multiple",
  requireAuth,
  requirePermission("dispute:update"),
  uploadMultiple.array("files", DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFiles),
  handleDisputeUploadError,
  async (req: Request, res: Response) => {
    const { disputeId } = req.params;
    const { descriptions } = req.body;
    const files = req.files as Express.Multer.File[];

    if (!files || files.length === 0) {
      throw createError(ERROR_CODES.INVALID_INPUT, "No files uploaded", {
        error: "No files uploaded",
      });
    }

    // Validate all files
    for (const file of files) {
      const validation = validateDisputeEvidenceFile(file);
      if (!validation.valid) {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          `File "${file.originalname}": ${validation.error}`,
          {
            error: `File "${file.originalname}": ${validation.error}`,
          },
        );
      }
    }

    // Security scan every file before anything is written to storage. If any
    // file fails, the whole batch is rejected.
    const securityResults: UploadGateResult[] = [];
    for (const file of files) {
      const security = await gateUpload(file, {
        userId: req.user?.id || null,
      });
      if (security.outcome === "infected") {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          `File "${file.originalname}" rejected: failed the security scan`,
          { error: security.reason },
        );
      }
      if (security.outcome === "quarantined") {
        throw createError(
          ERROR_CODES.INVALID_INPUT,
          `File "${file.originalname}" quarantined: scan engine unavailable, please retry later`,
          { error: security.reason },
        );
      }
      if (security.outcome === "error" || !security.record) {
        throw createError(
          ERROR_CODES.INTERNAL_ERROR,
          "Upload security scan failed",
          { error: security.reason },
        );
      }
      securityResults.push(security);
    }

    try {
      // Upload all files to S3
      const uploadResults = await uploadMultipleDisputeEvidenceToS3(
        disputeId,
        files,
        req.user?.id || "unknown",
      );

      // Check for upload failures
      const failedUploads = uploadResults.filter((r) => !r.success);
      if (failedUploads.length > 0) {
        throw createError(
          ERROR_CODES.INTERNAL_ERROR,
          "Some files failed to upload",
          {
            error: "Some files failed to upload",
          },
        );
      }

      // Save evidence records
      const evidenceRecords = [];
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const uploadResult = uploadResults[i];
        const description = Array.isArray(descriptions)
          ? descriptions[i]
          : descriptions;

        // Attach the stored key to the security record for integrity audits.
        if (uploadResult.success && uploadResult.key) {
          await linkStoredKey(
            securityResults[i].record!.id,
            uploadResult.key,
          ).catch((err: unknown) => {
            console.error("Failed to link security record to S3 key:", err);
          });
        }

        const evidence = await disputeService.addEvidence(
          disputeId,
          file.originalname,
          file.mimetype,
          file.size,
          uploadResult.key!,
          uploadResult.fileUrl!,
          req.user?.id || "unknown",
          description,
        );
        evidenceRecords.push(evidence);
      }

      return res.status(201).json(evidenceRecords);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to upload evidence";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        {
          error: message,
        },
      );
    }
  },
);

/**
 * GET /api/disputes/:disputeId/evidence
 */
disputeRoutes.get(
  "/:disputeId/evidence",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    try {
      const evidence = await disputeService.getEvidence(req.params.disputeId);
      return res.json(evidence);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to get evidence";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        {
          error: message,
        },
      );
    }
  },
);

// ---------------------------------------------------------------------------
// #413 Dispute Evidence Organization — categorization, search, timeline
// ---------------------------------------------------------------------------

/**
 * Valid evidence categories for #413.
 * Covers transaction proof, communication logs, and merchant statements.
 */
export const EVIDENCE_CATEGORIES = [
  "transaction_proof",
  "communication",
  "merchant_statement",
  "identity_document",
  "bank_statement",
  "screenshot",
  "other",
] as const;

export type EvidenceCategory = (typeof EVIDENCE_CATEGORIES)[number];

/**
 * PATCH /api/disputes/:disputeId/evidence/:evidenceId/category
 *
 * Update the category of a specific evidence item.
 * Body: { category: EvidenceCategory }
 */
disputeRoutes.patch(
  "/:disputeId/evidence/:evidenceId/category",
  requireAuth,
  requirePermission("dispute:update"),
  async (req: Request, res: Response) => {
    const { disputeId, evidenceId } = req.params;
    const { category } = req.body;

    if (
      !category ||
      !EVIDENCE_CATEGORIES.includes(category as EvidenceCategory)
    ) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        `Field "category" must be one of: ${EVIDENCE_CATEGORIES.join(", ")}`,
        { error: `Invalid category: ${category}` },
      );
    }

    try {
      const updated = await disputeService.updateEvidenceCategory(
        disputeId,
        evidenceId,
        category as EvidenceCategory,
      );
      if (!updated) {
        throw createError(ERROR_CODES.NOT_FOUND, "Evidence item not found", {
          error: "Evidence item not found",
        });
      }
      return res.json(updated);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to update category";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        { error: message },
      );
    }
  },
);

/**
 * PATCH /api/disputes/:disputeId/evidence/reorder
 *
 * Drag-and-drop reorder: update the display_order of multiple evidence items.
 * Body: { order: Array<{ id: string; position: number }> }
 */
disputeRoutes.patch(
  "/:disputeId/evidence/reorder",
  requireAuth,
  requirePermission("dispute:update"),
  async (req: Request, res: Response) => {
    const { disputeId } = req.params;
    const { order } = req.body;

    if (
      !Array.isArray(order) ||
      order.length === 0 ||
      !order.every(
        (o: unknown) =>
          o !== null &&
          typeof o === "object" &&
          typeof (o as any).id === "string" &&
          typeof (o as any).position === "number",
      )
    ) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        'Field "order" must be an array of { id: string; position: number }',
        { error: "Invalid order format" },
      );
    }

    try {
      const updated = await disputeService.reorderEvidence(disputeId, order);
      return res.json({ reordered: updated });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to reorder evidence";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        { error: message },
      );
    }
  },
);

/**
 * GET /api/disputes/:disputeId/evidence/search
 *
 * Search evidence by keyword (searches file name, description, and category).
 * Query: q (search term), category (optional filter)
 */
disputeRoutes.get(
  "/:disputeId/evidence/search",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    const { disputeId } = req.params;
    const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
    const category =
      typeof req.query.category === "string"
        ? (req.query.category as EvidenceCategory)
        : undefined;

    if (!q && !category) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        'At least one of "q" or "category" query params is required',
        { error: "Missing search parameters" },
      );
    }

    if (
      category &&
      !EVIDENCE_CATEGORIES.includes(category as EvidenceCategory)
    ) {
      throw createError(
        ERROR_CODES.INVALID_INPUT,
        `Invalid category. Must be one of: ${EVIDENCE_CATEGORIES.join(", ")}`,
        { error: `Invalid category: ${category}` },
      );
    }

    try {
      const results = await disputeService.searchEvidence(
        disputeId,
        q,
        category,
      );
      return res.json({ count: results.length, evidence: results });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Evidence search failed";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        { error: message },
      );
    }
  },
);

/**
 * GET /api/disputes/:disputeId/timeline
 *
 * Returns a chronological timeline of all events for a dispute:
 * status changes, evidence uploads, notes, and assignments.
 */
disputeRoutes.get(
  "/:disputeId/timeline",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    try {
      const timeline = await disputeService.getTimeline(req.params.disputeId);
      return res.json({ count: timeline.length, timeline });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to retrieve timeline";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        { error: message },
      );
    }
  },
);

/**
 * GET /api/disputes/:disputeId/evidence/by-category
 *
 * Returns evidence grouped by category for the organized review UI.
 */
disputeRoutes.get(
  "/:disputeId/evidence/by-category",
  requireAuth,
  requirePermission("dispute:read"),
  async (req: Request, res: Response) => {
    try {
      const evidence = await disputeService.getEvidenceByCategory(
        req.params.disputeId,
      );
      return res.json(evidence);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to retrieve categorized evidence";
      throw createError(
        message.includes("not found")
          ? ERROR_CODES.NOT_FOUND
          : ERROR_CODES.INTERNAL_ERROR,
        message,
        { error: message },
      );
    }
  },
);
