import multer from 'multer';
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import path from 'path';
import { DISPUTE_EVIDENCE_UPLOAD_LIMITS } from '../config/uploadLimits';

/**
 * Allowed file types for dispute evidence
 */
const ALLOWED_MIME_TYPES = [...DISPUTE_EVIDENCE_UPLOAD_LIMITS.allowedMimeTypes];

/**
 * Maximum file size: 10MB
 */
const MAX_FILE_SIZE = DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFileSizeBytes;

/**
 * Maximum number of files per upload
 */
const MAX_FILES = DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFiles;

/**
 * File filter to validate file types
 */
const fileFilter = (
  req: Request,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback
) => {
  if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error(
        `Invalid file type. Allowed types: ${ALLOWED_MIME_TYPES.join(', ')}`
      )
    );
  }
};

/**
 * Generate unique filename with timestamp and random hash
 */
export const generateUniqueFilename = (originalFilename: string): string => {
  const timestamp = Date.now();
  const randomHash = crypto.randomBytes(8).toString('hex');
  const extension = path.extname(originalFilename);
  const basename = path.basename(originalFilename, extension);
  
  // Sanitize basename (remove special characters)
  const sanitizedBasename = basename.replace(/[^a-zA-Z0-9-_]/g, '_');
  
  return `${sanitizedBasename}-${timestamp}-${randomHash}${extension}`;
};

/**
 * Generate S3 key path for dispute evidence
 */
export const generateDisputeS3Key = (disputeId: string, filename: string): string => {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  
  return `dispute-evidence/${year}/${month}/${disputeId}/${filename}`;
};

/**
 * Multer memory storage configuration
 * Files are stored in memory temporarily before uploading to S3
 */
const storage = multer.memoryStorage();

/**
 * Multer upload middleware configuration for single file
 */
export const uploadSingle = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,
    fields: DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFields,
    fieldSize: DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFieldSizeBytes,
  },
});

/**
 * Multer upload middleware configuration for multiple files
 */
export const uploadMultiple = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: MAX_FILES,
    fields: DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFields,
    fieldSize: DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFieldSizeBytes,
  },
});

/**
 * Translate multer limit errors on dispute evidence routes into controlled
 * client errors instead of generic 500s. Place directly after the multer
 * middleware in the route chain.
 */
export const handleDisputeUploadError = (
  err: Error,
  _req: Request,
  res: Response,
  next: NextFunction,
): void => {
  if (err instanceof multer.MulterError) {
    switch (err.code) {
      case 'LIMIT_FILE_SIZE':
        res.status(413).json({ error: disputeUploadErrorMessages.FILE_TOO_LARGE });
        return;
      case 'LIMIT_FILE_COUNT':
        res.status(400).json({ error: disputeUploadErrorMessages.TOO_MANY_FILES });
        return;
      case 'LIMIT_UNEXPECTED_FILE':
        res.status(400).json({
          error: `Unexpected file field; only "${err.field}" is accepted`,
        });
        return;
      default:
        res.status(400).json({ error: disputeUploadErrorMessages.UPLOAD_FAILED });
        return;
    }
  }
  next(err);
};

/**
 * Error messages for upload validation
 */
export const disputeUploadErrorMessages = {
  FILE_TOO_LARGE: `File size exceeds maximum limit of ${MAX_FILE_SIZE / (1024 * 1024)}MB`,
  INVALID_FILE_TYPE: `Invalid file type. Allowed types: ${ALLOWED_MIME_TYPES.join(', ')}`,
  TOO_MANY_FILES: `Maximum ${MAX_FILES} files allowed per upload`,
  NO_FILE_UPLOADED: 'No file uploaded',
  UPLOAD_FAILED: 'File upload failed',
};