/**
 * Per-route multipart upload limits.
 *
 * General JSON body limits (express.json `REQUEST_SIZE_LIMIT`) do not apply
 * to multipart/form-data uploads. Every upload route must therefore declare
 * its own byte limits, file-count limits and accepted content types so the
 * multer `limits`/`fileFilter` configuration, the route-level validation and
 * the OpenAPI documentation all share a single source of truth.
 */

const MB = 1024 * 1024;
const KB = 1024;

export interface MultipartUploadLimits {
  /** Maximum size of a single uploaded file, in bytes. */
  maxFileSizeBytes: number;
  /** Maximum number of files per request. */
  maxFiles: number;
  /** Maximum number of non-file form fields per request. */
  maxFields: number;
  /** Maximum size of a single non-file form field, in bytes. */
  maxFieldSizeBytes: number;
  /** MIME types accepted by the route (client-declared; verified against magic bytes). */
  allowedMimeTypes: readonly string[];
  /** File extensions accepted by the route. */
  allowedExtensions: readonly string[];
}

/** KYC document upload (POST /api/kyc/documents/upload). */
export const KYC_DOCUMENT_UPLOAD_LIMITS: MultipartUploadLimits = {
  maxFileSizeBytes: 5 * MB,
  maxFiles: 1,
  maxFields: 12,
  maxFieldSizeBytes: 64 * KB,
  allowedMimeTypes: [
    "application/pdf",
    "image/jpeg",
    "image/jpg",
    "image/png",
  ],
  allowedExtensions: [".pdf", ".jpeg", ".jpg", ".png"],
};

/** Dispute evidence upload (POST /api/disputes/:id/evidence[/multiple]). */
export const DISPUTE_EVIDENCE_UPLOAD_LIMITS: MultipartUploadLimits = {
  maxFileSizeBytes: 10 * MB,
  maxFiles: 5,
  maxFields: 12,
  maxFieldSizeBytes: 64 * KB,
  allowedMimeTypes: [
    "application/pdf",
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/gif",
    "text/plain",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ],
  allowedExtensions: [
    ".pdf",
    ".jpeg",
    ".jpg",
    ".png",
    ".gif",
    ".txt",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
  ],
};

/**
 * Archive (zip container) safety budget applied to uploads whose content is
 * a zip container (docx/xlsx evidence). Guards against archive bombs: an
 * upload may declare a huge decompressed size or an extreme compression
 * ratio even though the compressed bytes are small.
 */
export interface ArchiveSafetyLimits {
  /** Maximum number of entries in the archive. */
  maxEntries: number;
  /** Maximum total decompressed size across all entries, in bytes. */
  maxTotalUncompressedBytes: number;
  /** Maximum decompressed/compressed ratio before the archive is flagged. */
  maxCompressionRatio: number;
}

export const DISPUTE_ARCHIVE_SAFETY_LIMITS: ArchiveSafetyLimits = {
  maxEntries: 128,
  maxTotalUncompressedBytes: 100 * MB,
  maxCompressionRatio: 100,
};
