/**
 * Security tests for multipart upload limits and content enforcement
 * (issue #811).
 *
 * Covers the three attack shapes called out in the issue:
 *   - oversized       → per-route multer byte limits return 413
 *   - malformed       → magic-byte inspection rejects spoofed content
 *   - archive bombs   → decompressed-size / ratio / entry-count budgets
 *
 * Also verifies the per-route file-count limits (extra parts rejected).
 */

import request from "supertest";
import express from "express";
import {
  inspectFileSignature,
  inspectArchiveSafety,
} from "../../src/services/fileSecurityService";
import { validateDisputeEvidenceFile } from "../../src/services/disputeS3Upload";
import {
  KYC_DOCUMENT_UPLOAD_LIMITS,
  DISPUTE_EVIDENCE_UPLOAD_LIMITS,
} from "../../src/config/uploadLimits";
import {
  validPdfBuffer,
  validPngBuffer,
  validJpegBuffer,
  validTextBuffer,
  oversizedPdfBuffer,
  scriptAsImageBuffer,
  executableAsPdfBuffer,
  safeZipBuffer,
  zipBombBuffer,
  manyEntriesZipBuffer,
  docxLikeBuffer,
  docxBombBuffer,
  asMulterFile,
} from "./uploadFixtures";

jest.mock("../../src/services/fileSecurityService", () => {
  const actual =
    jest.requireActual("../../src/services/fileSecurityService");
  return {
    ...actual,
    gateUpload: jest.fn(),
    linkStoredKey: jest.fn().mockResolvedValue(undefined),
  };
});

jest.mock("../../src/services/s3Upload", () => ({
  uploadToS3: jest.fn(),
  validateFile: jest.fn().mockReturnValue({ valid: true }),
}));

jest.mock("../../src/middleware/auth", () => ({
  authenticateToken: (
    req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    req.jwtUser = { userId: "test-user-id", role: "user" } as never;
    req.user = { id: "test-user-id", role: "user" } as never;
    next();
  },
}));

import {
  gateUpload,
  linkStoredKey,
} from "../../src/services/fileSecurityService";
import { uploadToS3 } from "../../src/services/s3Upload";
import { createKYCRoutes } from "../../src/routes/kycRoutes";

const mockGateUpload = gateUpload as jest.Mock;
const mockLinkStoredKey = linkStoredKey as jest.Mock;
const mockUploadToS3 = uploadToS3 as jest.Mock;

function cleanSecurityRecord() {
  return {
    id: "sec-1",
    userId: "test-user-id",
    originalFilename: "doc.pdf",
    storedKey: null,
    declaredMimetype: "application/pdf",
    detectedMimetype: "application/pdf",
    sha256: "a".repeat(64),
    sizeBytes: 10,
    scanStatus: "clean",
    scanEngine: "embedded-signature-scanner",
    threats: [],
    quarantineUntil: null,
    scannedAt: new Date(),
    approvedAt: null,
    createdAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// Signature inspection (magic bytes)
// ---------------------------------------------------------------------------

describe("File signature inspection", () => {
  const kycPolicy = {
    allowedDeclaredTypes: [...KYC_DOCUMENT_UPLOAD_LIMITS.allowedMimeTypes],
    rejectArchives: true,
  };

  it("accepts content whose magic bytes match the declared type", () => {
    expect(
      inspectFileSignature(
        asMulterFile({
          buffer: validPdfBuffer(),
          mimetype: "application/pdf",
          originalname: "invoice.pdf",
        }),
        kycPolicy,
      ).ok,
    ).toBe(true);

    expect(
      inspectFileSignature(
        asMulterFile({
          buffer: validPngBuffer(),
          mimetype: "image/png",
          originalname: "id.png",
        }),
        kycPolicy,
      ).ok,
    ).toBe(true);

    expect(
      inspectFileSignature(
        asMulterFile({
          buffer: validJpegBuffer(),
          mimetype: "image/jpeg",
          originalname: " selfie.jpg ",
        }),
        kycPolicy,
      ).ok,
    ).toBe(true);
  });

  it("rejects a script renamed to .png (no image magic bytes)", () => {
    const result = inspectFileSignature(
      asMulterFile({
        buffer: scriptAsImageBuffer(),
        mimetype: "image/png",
        originalname: "photo.png",
      }),
      kycPolicy,
    );
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("does not match");
  });

  it("rejects an executable smuggled into a PDF upload", () => {
    const result = inspectFileSignature(
      asMulterFile({
        buffer: executableAsPdfBuffer(),
        mimetype: "application/pdf",
        originalname: "doc.pdf",
      }),
      kycPolicy,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects archives on routes that must not receive them (KYC)", () => {
    const result = inspectFileSignature(
      asMulterFile({
        buffer: safeZipBuffer(),
        mimetype: "application/pdf",
        originalname: "passport.pdf",
      }),
      kycPolicy,
    );
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not permitted");
  });

  it("rejects an empty file", () => {
    const result = inspectFileSignature(
      asMulterFile({ buffer: Buffer.alloc(0), mimetype: "application/pdf" }),
      kycPolicy,
    );
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("Empty file");
  });

  it("rejects a declared type that the route does not accept", () => {
    const result = inspectFileSignature(
      asMulterFile({
        buffer: validTextBuffer(),
        mimetype: "text/plain",
        originalname: "notes.txt",
      }),
      kycPolicy,
    );
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not allowed");
  });
});

// ---------------------------------------------------------------------------
// Archive-bomb detection
// ---------------------------------------------------------------------------

describe("Archive safety inspection", () => {
  it("accepts a legitimate small archive", () => {
    const result = inspectArchiveSafety(safeZipBuffer());
    expect(result.ok).toBe(true);
    expect(result.entryCount).toBe(1);
    expect(result.totalUncompressedBytes).toBe(1024);
  });

  it("rejects an archive whose declared decompressed size is a bomb", () => {
    const result = inspectArchiveSafety(zipBombBuffer());
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("decompresses to more than");
  });

  it("rejects an archive with an excessive entry count", () => {
    const result = inspectArchiveSafety(manyEntriesZipBuffer(200));
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("more than the permitted");
  });

  it("ignores non-archive buffers", () => {
    const result = inspectArchiveSafety(validPdfBuffer());
    expect(result.ok).toBe(true);
    expect(result.entryCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Dispute evidence validation (shared limits + content checks)
// ---------------------------------------------------------------------------

describe("Dispute evidence file validation", () => {
  it("accepts a valid PDF", () => {
    const result = validateDisputeEvidenceFile(
      asMulterFile({
        buffer: validPdfBuffer(),
        mimetype: "application/pdf",
        originalname: "receipt.pdf",
      }),
    );
    expect(result.valid).toBe(true);
  });

  it("rejects a file over the per-route byte limit", () => {
    const oversized = oversizedPdfBuffer(
      DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFileSizeBytes + 1,
    );
    const result = validateDisputeEvidenceFile(
      asMulterFile({
        buffer: oversized,
        mimetype: "application/pdf",
        originalname: "huge.pdf",
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain("exceeds maximum limit");
  });

  it("rejects spoofed content (script renamed to .png)", () => {
    const result = validateDisputeEvidenceFile(
      asMulterFile({
        buffer: scriptAsImageBuffer(),
        mimetype: "image/png",
        originalname: "screenshot.png",
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain("does not match");
  });

  it("accepts a legitimate docx (zip container) within the archive budget", () => {
    const result = validateDisputeEvidenceFile(
      asMulterFile({
        buffer: docxLikeBuffer(),
        mimetype:
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        originalname: "contract.docx",
      }),
    );
    expect(result.valid).toBe(true);
  });

  it("rejects a docx that is an archive bomb", () => {
    const result = validateDisputeEvidenceFile(
      asMulterFile({
        buffer: docxBombBuffer(),
        mimetype:
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        originalname: "contract.docx",
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain("decompresses to more than");
  });

  it("rejects a zip archive declared as a PDF", () => {
    const result = validateDisputeEvidenceFile(
      asMulterFile({
        buffer: safeZipBuffer(),
        mimetype: "application/pdf",
        originalname: "evidence.pdf",
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain("does not match");
  });
});

// ---------------------------------------------------------------------------
// Route-level enforcement (multer per-route limits + content checks)
// ---------------------------------------------------------------------------

describe("KYC document upload limits (POST /api/kyc/documents/upload)", () => {
  let app: express.Application;
  let mockPool: { query: jest.Mock };

  beforeEach(() => {
    jest.clearAllMocks();
    mockPool = { query: jest.fn() };
    app = express();
    app.use(express.json());
    app.use("/api/kyc", createKYCRoutes(mockPool as never));

    mockGateUpload.mockResolvedValue({
      outcome: "clean",
      record: cleanSecurityRecord(),
    });
    mockLinkStoredKey.mockResolvedValue(undefined);
    mockUploadToS3.mockResolvedValue({
      success: true,
      fileUrl: "https://bucket.s3.amazonaws.com/kyc-documents/file.pdf",
      key: "kyc-documents/2026/10/test-user-id/file.pdf",
    });
  });

  it("rejects an oversized file with 413", async () => {
    const response = await request(app)
      .post("/api/kyc/documents/upload")
      .attach(
        "document",
        oversizedPdfBuffer(KYC_DOCUMENT_UPLOAD_LIMITS.maxFileSizeBytes + 1024),
        "huge.pdf",
      )
      .field("applicant_id", "app-1");

    expect(response.status).toBe(413);
    expect(response.body.error).toContain("exceeds maximum limit");
    expect(mockGateUpload).not.toHaveBeenCalled();
  });

  it("rejects an archive disguised as a PDF with 400", async () => {
    const response = await request(app)
      .post("/api/kyc/documents/upload")
      .attach("document", safeZipBuffer(), "passport.pdf")
      .field("applicant_id", "app-1");

    expect(response.status).toBe(400);
    expect(response.body.error).toContain("not permitted");
    expect(mockUploadToS3).not.toHaveBeenCalled();
  });

  it("rejects malformed content (script renamed to .png) with 400", async () => {
    const response = await request(app)
      .post("/api/kyc/documents/upload")
      .attach("document", scriptAsImageBuffer(), "photo.png")
      .field("applicant_id", "app-1");

    expect(response.status).toBe(400);
    expect(response.body.error).toContain("does not match");
    expect(mockUploadToS3).not.toHaveBeenCalled();
  });

  it("rejects unexpected extra file parts with 400", async () => {
    const response = await request(app)
      .post("/api/kyc/documents/upload")
      .attach("document", validPdfBuffer(), "doc.pdf")
      .attach("extra", validPdfBuffer(), "second.pdf")
      .field("applicant_id", "app-1");

    expect(response.status).toBe(400);
    expect(response.body.error).toContain("Unexpected file field");
  });

  it("stores a valid PDF that passes signature inspection", async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ id: 1 }] } as never) // ownership
      .mockResolvedValueOnce({
        rows: [
          {
            id: "doc-id",
            file_url: "https://bucket.s3.amazonaws.com/file.pdf",
            created_at: new Date(),
          },
        ],
      } as never);

    const response = await request(app)
      .post("/api/kyc/documents/upload")
      .attach("document", validPdfBuffer(), "invoice.pdf")
      .field("applicant_id", "app-1");

    expect(response.status).toBe(201);
    expect(mockGateUpload).toHaveBeenCalledTimes(1);
    expect(mockUploadToS3).toHaveBeenCalledTimes(1);
  });
});

describe("Dispute evidence upload limits (POST /api/disputes/:id/evidence)", () => {
  let app: express.Application;

  beforeAll(() => {
    jest.resetModules();
    jest.doMock("../../src/middleware/auth", () => ({
      requireAuth: (req: express.Request, _res: express.Response, next: express.NextFunction) => {
        req.user = { id: "user-1", role: "user" } as never;
        next();
      },
    }));
    jest.doMock("../../src/middleware/rbac", () => ({
      requirePermission:
        () => (_req: unknown, _res: unknown, next: express.NextFunction) =>
          next(),
    }));
    jest.doMock("../../src/services/dispute", () => ({
      DisputeService: jest.fn().mockImplementation(() => ({
        addEvidence: jest.fn().mockResolvedValue({ id: "evidence-1" }),
      })),
    }));
    jest.doMock("../../src/services/disputeS3Upload", () => {
      const actual = jest.requireActual("../../src/services/disputeS3Upload");
      return {
        ...actual,
        uploadDisputeEvidenceToS3: jest.fn().mockResolvedValue({
          success: true,
          fileUrl: "https://bucket.s3.amazonaws.com/evidence.pdf",
          key: "dispute-evidence/2026/10/dispute-1/evidence.pdf",
        }),
        uploadMultipleDisputeEvidenceToS3: jest.fn().mockResolvedValue([
          {
            success: true,
            fileUrl: "https://bucket.s3.amazonaws.com/a.pdf",
            key: "dispute-evidence/2026/10/dispute-1/a.pdf",
          },
        ]),
      };
    });
    jest.doMock("../../src/jobs/disputeSlaJob", () => ({
      generateDisputeSlaReport: jest.fn(),
      runDisputeSlaJob: jest.fn(),
    }));
  });

  beforeEach(() => {
    jest.clearAllMocks();
    app = express();
    app.use(express.json());
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { disputeRoutes } = require("../../src/routes/disputes");
    app.use("/api/disputes", disputeRoutes);
    mockGateUpload.mockResolvedValue({
      outcome: "clean",
      record: cleanSecurityRecord(),
    });
  });

  it("rejects an oversized evidence file with 413", async () => {
    const response = await request(app)
      .post("/api/disputes/dispute-1/evidence")
      .attach(
        "file",
        oversizedPdfBuffer(DISPUTE_EVIDENCE_UPLOAD_LIMITS.maxFileSizeBytes + 1024),
        "huge.pdf",
      );

    expect(response.status).toBe(413);
    expect(response.body.error).toContain("exceeds maximum limit");
  });

  it("rejects a docx archive bomb with 400", async () => {
    const response = await request(app)
      .post("/api/disputes/dispute-1/evidence")
      .attach("file", docxBombBuffer(), "contract.docx");

    expect(response.status).toBe(400);
    expect(response.body.error).toContain("decompresses to more than");
    expect(mockGateUpload).not.toHaveBeenCalled();
  });

  it("rejects spoofed evidence content with 400", async () => {
    const response = await request(app)
      .post("/api/disputes/dispute-1/evidence")
      .attach("file", scriptAsImageBuffer(), "photo.png");

    expect(response.status).toBe(400);
    expect(response.body.error).toContain("does not match");
  });

  it("accepts legitimate PDF evidence", async () => {
    const response = await request(app)
      .post("/api/disputes/dispute-1/evidence")
      .attach("file", validPdfBuffer(), "receipt.pdf")
      .field("description", "proof of payment");

    expect(response.status).toBe(201);
    expect(mockGateUpload).toHaveBeenCalledTimes(1);
  });
});
