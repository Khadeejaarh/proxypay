import multer from "multer";
import { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import path from "path";
import sharp from "sharp";
import { KYC_DOCUMENT_UPLOAD_LIMITS } from "../config/uploadLimits";

/**
 * Allowed file types for KYC documents
 */
const ALLOWED_MIME_TYPES = [...KYC_DOCUMENT_UPLOAD_LIMITS.allowedMimeTypes];

/**
 * Maximum file size for KYC documents (5MB)
 */
const MAX_FILE_SIZE = KYC_DOCUMENT_UPLOAD_LIMITS.maxFileSizeBytes;

/**
 * File filter to validate file types
 */
const fileFilter = (
  req: Request,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback,
) => {
  // Accept file at middleware stage; route-level validation returns controlled errors.
  cb(null, true);
};

/**
 * Generate unique filename with timestamp and random hash
 */
export const generateUniqueFilename = (originalFilename: string): string => {
  const timestamp = Date.now();
  const randomHash = crypto.randomBytes(8).toString("hex");
  const extension = path.extname(originalFilename);
  const basename = path.basename(originalFilename, extension);

  // Sanitize basename (remove special characters)
  const sanitizedBasename = basename.replace(/[^a-zA-Z0-9-_]/g, "_");

  return `${sanitizedBasename}-${timestamp}-${randomHash}${extension}`;
};

/**
 * Generate S3 key path for KYC documents
 */
export const generateS3Key = (userId: string, filename: string): string => {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");

  return `kyc-documents/${year}/${month}/${userId}/${filename}`;
};

/**
 * Multer memory storage configuration
 * Files are stored in memory temporarily before uploading to S3
 */
const storage = multer.memoryStorage();

/**
 * Multer upload middleware configuration
 */
export const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 10, // Increased to allow multiple standard and custom files per request
    fields: 25,
    fieldSize: 64 * 1024,
  },
});

/**
 * Per-route multer instance for KYC document uploads. Enforces the
 * route-specific byte and file-count limits from
 * `KYC_DOCUMENT_UPLOAD_LIMITS` — general JSON body limits do not apply to
 * multipart uploads, so each upload route must declare its own budget.
 */
export const kycDocumentUpload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: KYC_DOCUMENT_UPLOAD_LIMITS.maxFileSizeBytes,
    files: KYC_DOCUMENT_UPLOAD_LIMITS.maxFiles,
    fields: KYC_DOCUMENT_UPLOAD_LIMITS.maxFields,
    fieldSize: KYC_DOCUMENT_UPLOAD_LIMITS.maxFieldSizeBytes,
  },
});

/**
 * Translate multer limit errors on the KYC upload route into controlled
 * client errors instead of generic 500s. Runs after `kycDocumentUpload` in
 * the route chain and only handles multer errors; anything else is passed
 * to the next error handler.
 */
export const handleKycUploadError = (
  err: Error,
  _req: Request,
  res: Response,
  next: NextFunction,
): void => {
  if (err instanceof multer.MulterError) {
    switch (err.code) {
      case "LIMIT_FILE_SIZE":
        res.status(413).json({ error: uploadErrorMessages.FILE_TOO_LARGE });
        return;
      case "LIMIT_FILE_COUNT":
        res.status(400).json({
          error: `Maximum ${KYC_DOCUMENT_UPLOAD_LIMITS.maxFiles} file allowed per upload`,
        });
        return;
      case "LIMIT_UNEXPECTED_FILE":
        res.status(400).json({
          error: `Unexpected file field; only "${err.field}" is accepted`,
        });
        return;
      default:
        res.status(400).json({ error: uploadErrorMessages.UPLOAD_FAILED });
        return;
    }
  }
  next(err);
};

/**
 * Error messages for upload validation
 */
export const uploadErrorMessages = {
  FILE_TOO_LARGE: `File size exceeds maximum limit of ${MAX_FILE_SIZE / (1024 * 1024)}MB`,
  INVALID_FILE_TYPE: `Invalid file type. Allowed types: ${ALLOWED_MIME_TYPES.join(", ")}`,
  NO_FILE_UPLOADED: "No file uploaded",
  UPLOAD_FAILED: "File upload failed",
};

/**
  Middleware to optimize image with sharp before s3 upload
 */

export const optimizeProfileImage = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  if (!req.file) {
    res.status(400).json({
      status: "fail",
      message: uploadErrorMessages.NO_FILE_UPLOADED,
    });
    return next();
  }

  if (!ALLOWED_MIME_TYPES.includes(req.file.mimetype)) {
    res.status(400).json({
      status: "fail",
      message: uploadErrorMessages.INVALID_FILE_TYPE,
    });
    return next();
  }

  try {
    const optimizedBuffer = await sharp(req.file.buffer)
      .resize(500, 500, { fit: "cover", position: "center" })
      .webp({ quality: 80 })
      .toBuffer();

    req.file.buffer = optimizedBuffer;
    req.file.mimetype = "image/webp";
    req.file.size = optimizedBuffer.length;

    const originalNameWithoutExt = req.file.originalname.replace(
      /\.[^/.]+$/,
      "",
    );
    req.file.originalname = `${originalNameWithoutExt}.webp`;

    next();
  } catch (error) {
    console.error("Image optimization error:", error);
    res.status(500).json({ error: "Failed to optimize image before upload" });
  }
};