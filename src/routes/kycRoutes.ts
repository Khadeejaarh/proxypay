import { NextFunction, Router } from "express";
import { Pool } from "pg";
import { KYCController } from "../controllers/kycController";
import { authenticateToken } from "../middleware/auth";
import {
  kycDocumentUpload,
  handleKycUploadError,
  uploadErrorMessages,
} from "../middleware/upload";
import { uploadToS3 } from "../services/s3Upload";
import {
  gateUpload,
  linkStoredKey,
  computeSha256,
  inspectFileSignature,
} from "../services/fileSecurityService";
import { KYC_DOCUMENT_UPLOAD_LIMITS } from "../config/uploadLimits";
import { Request, Response } from "express";
import { ERROR_CODES } from "../constants/errorCodes";
import { createError } from "../middleware/errorHandler";

const COMPLIANCE_OFFICER_ROLE = "compliance_officer";
const REDACTED_FILE_URL = "[REDACTED]";

function validateUploadFile(file: Express.Multer.File): {
  valid: boolean;
  error?: string;
} {
  const limits = KYC_DOCUMENT_UPLOAD_LIMITS;
  const filename = String(file.originalname || "").toLowerCase();

  const hasAllowedMimeType = limits.allowedMimeTypes.includes(file.mimetype);
  const hasAllowedExtension = limits.allowedExtensions.some((ext) =>
    filename.endsWith(ext),
  );

  if (!hasAllowedMimeType && !hasAllowedExtension) {
    return {
      valid: false,
      error: uploadErrorMessages.INVALID_FILE_TYPE,
    };
  }

  if (file.size > limits.maxFileSizeBytes) {
    return {
      valid: false,
      error: uploadErrorMessages.FILE_TOO_LARGE,
    };
  }

  // Inspect the actual content (magic bytes): reject spoofed extensions,
  // polyglots and archives smuggled in as identity documents.
  const signature = inspectFileSignature(file, {
    allowedDeclaredTypes: [...limits.allowedMimeTypes],
    rejectArchives: true,
  });
  if (!signature.ok) {
    return {
      valid: false,
      error: signature.reason || uploadErrorMessages.INVALID_FILE_TYPE,
    };
  }

  return { valid: true };
}

function canViewRawKycUploads(req: Request): boolean {
  return req.jwtUser?.role === COMPLIANCE_OFFICER_ROLE;
}

function maskFileUrl<T extends { file_url?: string | null }>(
  document: T,
  canViewRaw: boolean,
): T {
  if (canViewRaw || !document.file_url) {
    return document;
  }

  return {
    ...document,
    file_url: REDACTED_FILE_URL,
  };
}

function annotateDocumentVisibility(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  res.locals.canViewRawKycUploads = canViewRawKycUploads(req);
  next();
}

export const createKYCRoutes = (db: Pool): Router => {
  const router = Router();
  const kycController = new KYCController(db);

  // All KYC routes require authentication
  router.use(authenticateToken);

  // Applicant management
  router.post("/applicants", kycController.createApplicant);
  router.get("/applicants/:applicantId", kycController.getApplicant);
  router.get(
    "/applicants/:applicantId/status",
    kycController.getVerificationStatus,
  );

  // Document upload (legacy - base64)
  router.post("/documents", kycController.uploadDocument);

  // File upload to S3
  router.post(
    "/documents/upload",
    annotateDocumentVisibility,
    kycDocumentUpload.single("document"),
    handleKycUploadError,
    async (req: Request, res: Response) => {
      try {
        const userId = req.jwtUser?.userId;
        if (!userId) {
          throw createError(
            ERROR_CODES.UNAUTHORIZED,
            "User not authenticated",
            {
              error: "User not authenticated",
            },
          );
        }

        // Get required metadata from request body first
        const { applicant_id, document_type, document_side } = req.body;

        if (!applicant_id) {
          throw createError(
            ERROR_CODES.INVALID_INPUT,
            "applicant_id is required",
            {
              error: "applicant_id is required",
            },
          );
        }

        // Check if file was uploaded
        if (!req.file) {
          throw createError(
            ERROR_CODES.INVALID_INPUT,
            uploadErrorMessages.NO_FILE_UPLOADED,
            {
              error: uploadErrorMessages.NO_FILE_UPLOADED,
            },
          );
        }

        // Validate file
        const validation = validateUploadFile(req.file);
        if (!validation.valid) {
          throw createError(ERROR_CODES.INVALID_INPUT, validation.error, {
            error: validation.error,
          });
        }

        // Security scan: antivirus + magic-byte type validation + integrity hash
        const security = await gateUpload(req.file, { userId });
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
            {
              error: security.reason,
            },
          );
        }

        // Verify user owns this applicant
        const accessQuery = `
        SELECT 1 FROM kyc_applicants 
        WHERE user_id = $1 AND applicant_id = $2
        LIMIT 1
      `;
        const accessResult = await db.query(accessQuery, [
          userId,
          applicant_id,
        ]);

        if (accessResult.rows.length === 0) {
          throw createError(ERROR_CODES.FORBIDDEN, "Access denied", {
            error: "Access denied",
          });
        }

        // Upload to S3
        const uploadResult = await uploadToS3({
          userId,
          file: req.file,
          metadata: {
            applicantId: applicant_id,
            documentType: document_type || "unknown",
            documentSide: document_side || "front",
            securityScan: security.record.scanStatus,
            sha256: computeSha256(req.file.buffer),
          },
        });

        // Attach the stored key to the security record for integrity audits.
        if (uploadResult.success && uploadResult.key) {
          await linkStoredKey(security.record.id, uploadResult.key).catch(
            (err: unknown) => {
              console.error("Failed to link security record to S3 key:", err);
            },
          );
        }

        if (!uploadResult.success) {
          throw createError(
            ERROR_CODES.INTERNAL_ERROR,
            uploadErrorMessages.UPLOAD_FAILED,
            {
              error: uploadErrorMessages.UPLOAD_FAILED,
              details: uploadResult.error,
            },
          );
        }

        // Store document reference in database
        const insertQuery = `
        INSERT INTO kyc_documents (
          user_id, 
          applicant_id, 
          document_type, 
          document_side, 
          file_url, 
          s3_key, 
          original_filename,
          file_size,
          mime_type
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, file_url, created_at
      `;

        const documentResult = await db.query(insertQuery, [
          userId,
          applicant_id,
          document_type || "unknown",
          document_side || "front",
          uploadResult.fileUrl,
          uploadResult.key,
          req.file.originalname,
          req.file.size,
          req.file.mimetype,
        ]);

        const canViewRaw = Boolean(res.locals.canViewRawKycUploads);

        res.status(201).json({
          success: true,
          data: {
            document_id: documentResult.rows[0].id,
            file_url: canViewRaw
              ? documentResult.rows[0].file_url
              : REDACTED_FILE_URL,
            applicant_id,
            uploaded_at: documentResult.rows[0].created_at,
          },
        });
      } catch (error) {
        console.error("Document upload error:", error);

        // Handle multer errors
        if (error instanceof Error) {
          if (error.message.includes("File too large")) {
            throw createError(
              ERROR_CODES.INVALID_INPUT,
              uploadErrorMessages.FILE_TOO_LARGE,
              {
                error: uploadErrorMessages.FILE_TOO_LARGE,
              },
            );
          }
          if (error.message.includes("Invalid file type")) {
            throw createError(
              ERROR_CODES.INVALID_INPUT,
              uploadErrorMessages.INVALID_FILE_TYPE,
              {
                error: uploadErrorMessages.INVALID_FILE_TYPE,
              },
            );
          }
        }

        throw createError(
          ERROR_CODES.INTERNAL_ERROR,
          "Failed to upload document",
          {
            message: error instanceof Error ? error.message : "Unknown error",
          },
        );
      }
    },
  );

  // Get user's uploaded documents
  router.get(
    "/documents",
    annotateDocumentVisibility,
    async (req: Request, res: Response) => {
      try {
        const userId = req.jwtUser?.userId;
        if (!userId) {
          throw createError(
            ERROR_CODES.UNAUTHORIZED,
            "User not authenticated",
            {
              error: "User not authenticated",
            },
          );
        }

        const query = `
        SELECT 
          id,
          applicant_id,
          document_type,
          document_side,
          file_url,
          original_filename,
          file_size,
          mime_type,
          created_at
        FROM kyc_documents
        WHERE user_id = $1
        ORDER BY created_at DESC
      `;

        const result = await db.query(query, [userId]);
        const canViewRaw = Boolean(res.locals.canViewRawKycUploads);
        const documents = result.rows.map((row) =>
          maskFileUrl(row, canViewRaw),
        );

        res.json({
          success: true,
          data: documents,
        });
      } catch (error) {
        console.error("Get documents error:", error);
        throw createError(
          ERROR_CODES.INTERNAL_ERROR,
          "Failed to retrieve documents",
          {
            message: error instanceof Error ? error.message : "Unknown error",
          },
        );
      }
    },
  );

  // Workflow management
  router.post("/workflow-runs", kycController.createWorkflowRun);

  // SDK token generation
  router.post("/sdk-token", kycController.generateSDKToken);

  // User KYC status
  router.get("/status", kycController.getUserKYCStatus);

  // Webhook endpoint (no auth required - verified by signature)
  router.post("/webhooks", kycController.handleWebhook);

  return router;
};

export default createKYCRoutes;
