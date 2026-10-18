/**
 * File Security Service
 *
 * Provides the security pipeline applied to every file upload:
 *
 *   1. Integrity      – SHA-256 content hash computed up-front so stored
 *                       objects can be verified later (tamper detection).
 *   2. Type validation– magic-byte sniffing that goes beyond the client
 *                       supplied extension / MIME type (catches polyglots
 *                       and spoofed extensions).
 *   3. Antivirus scan – scans the buffer for known threat signatures.
 *                       Uses ClamAV (clamd, INSTREAM protocol) when
 *                       CLAMAV_HOST / CLAMAV_PORT are configured, and falls
 *                       back to an embedded signature scanner otherwise.
 *   4. Quarantine     – uploads whose scan is inconclusive are held for a
 *                       configurable quarantine period before they may be
 *                       approved. Expired quarantines are auto-released.
 *
 * Every scan outcome is persisted in `upload_security_records` so there is
 * a full audit trail of what was uploaded, what the scanner said, and when
 * the object was approved.
 */

import { createHash } from "crypto";
import { connect } from "net";
import { pool } from "../config/database";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ScanStatus =
  | "pending"
  | "clean"
  | "infected"
  | "quarantined"
  | "approved"
  | "rejected";

export interface UploadSecurityRecord {
  id: string;
  userId: string | null;
  originalFilename: string;
  storedKey: string | null;
  declaredMimetype: string;
  detectedMimetype: string | null;
  sha256: string;
  sizeBytes: number;
  scanStatus: ScanStatus;
  scanEngine: string | null;
  threats: string[];
  quarantineUntil: Date | null;
  scannedAt: Date | null;
  approvedAt: Date | null;
  createdAt: Date;
}

export interface ScanOutcome {
  status: "clean" | "infected" | "error";
  threats: string[];
  engine: string;
  detectedMimetype: string | null;
  error?: string;
}

export interface UploadGateResult {
  outcome: "clean" | "infected" | "quarantined" | "error";
  record: UploadSecurityRecord | null;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CLAMAV_HOST = process.env.CLAMAV_HOST;
const CLAMAV_PORT = Number.parseInt(process.env.CLAMAV_PORT || "3310", 10);
const CLAMAV_TIMEOUT_MS = Number.parseInt(
  process.env.CLAMAV_TIMEOUT_MS || "10000",
  10,
);
const DEFAULT_QUARANTINE_MINUTES = Number.parseInt(
  process.env.UPLOAD_QUARANTINE_MINUTES || "1440", // 24h
  10,
);
const HEURISTIC_ENGINE = "embedded-signature-scanner";
const CLAMAV_ENGINE = "clamav";

/** The well-known EICAR test file – guaranteed to be flagged by AV engines. */
export const EICAR_TEST_STRING =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

// ---------------------------------------------------------------------------
// Integrity
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 digest of a file buffer. This is the integrity anchor
 * stored alongside every upload record.
 */
export function computeSha256(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}

/**
 * Verify that a buffer still hashes to the recorded digest. Returns false
 * for any tampering, truncation or corruption since the hash was recorded.
 */
export function verifyFileIntegrity(
  buffer: Buffer,
  expectedSha256: string,
): boolean {
  if (!expectedSha256) return false;
  return computeSha256(buffer) === expectedSha256.toLowerCase();
}

// ---------------------------------------------------------------------------
// File type validation beyond the extension
// ---------------------------------------------------------------------------

interface MagicSignature {
  mime: string;
  match: (buf: Buffer) => boolean;
}

const MAGIC_SIGNATURES: MagicSignature[] = [
  {
    mime: "application/pdf",
    match: (buf) =>
      buf.length >= 5 && buf.slice(0, 5).toString("latin1") === "%PDF-",
  },
  {
    mime: "image/png",
    match: (buf) =>
      buf.length >= 8 &&
      buf
        .slice(0, 8)
        .equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  },
  {
    mime: "image/jpeg",
    match: (buf) =>
      buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff,
  },
  {
    mime: "image/gif",
    match: (buf) =>
      buf.length >= 6 &&
      (buf.slice(0, 6).toString("ascii") === "GIF87a" ||
        buf.slice(0, 6).toString("ascii") === "GIF89a"),
  },
  {
    mime: "application/zip",
    match: (buf) =>
      buf.length >= 4 &&
      buf[0] === 0x50 &&
      buf[1] === 0x4b &&
      (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07),
  },
  {
    // Legacy Microsoft OLE2 compound document (.doc / .xls)
    mime: "application/x-ole-storage",
    match: (buf) =>
      buf.length >= 8 &&
      buf
        .slice(0, 8)
        .equals(
          Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
        ),
  },
  {
    mime: "text/plain",
    match: (buf) =>
      buf.length > 0 &&
      !MAGIC_SIGNATURES.some(
        (sig) => sig.mime !== "text/plain" && sig.match(buf),
      ),
  },
];

/**
 * Sniff the real file type from magic bytes, independent of the filename
 * extension or the declared MIME type supplied by the client.
 */
export function sniffMimeType(buffer: Buffer): string | null {
  if (!buffer || buffer.length === 0) return null;
  for (const sig of MAGIC_SIGNATURES) {
    if (sig.match(buffer)) return sig.mime;
  }
  return null;
}

/**
 * Compare the declared MIME type with the sniffed magic bytes. A mismatch
 * is a strong signal of a spoofed extension (e.g. a script renamed to .png).
 */
export function detectMimeMismatch(
  declaredMimetype: string,
  buffer: Buffer,
): { mismatch: boolean; declared: string; detected: string | null } {
  const detected = sniffMimeType(buffer);
  const normalizedDeclared = (declaredMimetype || "")
    .toLowerCase()
    .split(";")[0]
    .trim();

  // image/jpg is a commonly mislabeled image/jpeg.
  const equivalent =
    normalizedDeclared === "image/jpg" && detected === "image/jpeg";

  return {
    mismatch: !equivalent && !!detected && detected !== normalizedDeclared,
    declared: normalizedDeclared,
    detected,
  };
}

// ---------------------------------------------------------------------------
// Content signature enforcement
// ---------------------------------------------------------------------------

/**
 * Detected content types that are acceptable matches for a given declared
 * MIME type. Office Open XML containers (docx/xlsx) are zip archives and
 * legacy .doc/.xls files are OLE2 compound documents, so their magic bytes
 * legitimately differ from the declared type.
 */
const SIGNATURE_EQUIVALENCES: Record<string, string[]> = {
  "image/jpg": ["image/jpeg"],
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
    "application/zip",
  ],
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
    "application/zip",
  ],
  "application/msword": ["application/x-ole-storage"],
  "application/vnd.ms-excel": ["application/x-ole-storage", "application/zip"],
};

const ARCHIVE_MIME_TYPES = new Set(["application/zip", "application/x-ole-storage"]);

export interface FileSignaturePolicy {
  /** Declared MIME types the route accepts. */
  allowedDeclaredTypes: string[];
  /**
   * Reject zip/OLE2 container content outright. Use for routes that must
   * never receive archives (e.g. KYC identity documents).
   */
  rejectArchives?: boolean;
}

export interface FileSignatureInspection {
  ok: boolean;
  reason?: string;
  detectedMimetype: string | null;
}

/**
 * Inspect the actual file content (magic bytes) against the route's
 * declared-type policy. Catches spoofed extensions, polyglot files and
 * archives smuggled in as allowed document types — checks that the
 * client-supplied MIME type and extension alone cannot provide.
 */
export function inspectFileSignature(
  file: { originalname?: string; mimetype?: string; buffer: Buffer },
  policy: FileSignaturePolicy,
): FileSignatureInspection {
  const buffer = file.buffer;
  if (!buffer || buffer.length === 0) {
    return {
      ok: false,
      reason: "Empty file uploaded",
      detectedMimetype: null,
    };
  }

  const declared = (file.mimetype || "").toLowerCase().split(";")[0].trim();
  if (!policy.allowedDeclaredTypes.includes(declared)) {
    return {
      ok: false,
      reason: `Declared file type "${declared || "unknown"}" is not allowed for this upload`,
      detectedMimetype: sniffMimeType(buffer),
    };
  }

  const detected = sniffMimeType(buffer);

  if (policy.rejectArchives && detected && ARCHIVE_MIME_TYPES.has(detected)) {
    return {
      ok: false,
      reason: "Archives and compound documents are not permitted for this upload",
      detectedMimetype: detected,
    };
  }

  const accepted = new Set<string>([declared]);
  for (const equivalent of SIGNATURE_EQUIVALENCES[declared] || []) {
    accepted.add(equivalent);
  }

  if (!detected || !accepted.has(detected)) {
    return {
      ok: false,
      reason: `File content (${detected || "unknown"}) does not match its declared type (${declared})`,
      detectedMimetype: detected,
    };
  }

  return { ok: true, detectedMimetype: detected };
}

// ---------------------------------------------------------------------------
// Archive-bomb detection
// ---------------------------------------------------------------------------

export interface ArchiveInspectionLimits {
  maxEntries: number;
  maxTotalUncompressedBytes: number;
  maxCompressionRatio: number;
}

export const DEFAULT_ARCHIVE_INSPECTION_LIMITS: ArchiveInspectionLimits = {
  maxEntries: 128,
  maxTotalUncompressedBytes: 100 * 1024 * 1024,
  maxCompressionRatio: 100,
};

export interface ArchiveInspection {
  ok: boolean;
  reason?: string;
  entryCount: number;
  totalUncompressedBytes: number;
  totalCompressedBytes: number;
}

const ZIP_LOCAL_HEADER_SIG = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const ZIP_CENTRAL_DIR_SIG = Buffer.from([0x50, 0x4b, 0x01, 0x02]);
const ZIP_EOCD_SIG = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const ZIP64_MARKER = 0xffffffff;

/**
 * Inspect a zip container for archive-bomb characteristics without ever
 * extracting (and therefore without ever inflating) its contents.
 *
 * The central directory always records the true uncompressed size of each
 * entry, so a small compressed payload claiming gigabytes of decompressed
 * content — or an entry count large enough to exhaust disk when extracted —
 * is detected up-front. Zip64 archives are rejected outright because their
 * sizes cannot be trusted from the 32-bit fields.
 *
 * Callers should only run this for buffers whose sniffed type is
 * `application/zip` (including zip-based office containers such as
 * docx/xlsx).
 */
export function inspectArchiveSafety(
  buffer: Buffer,
  limits: ArchiveInspectionLimits = DEFAULT_ARCHIVE_INSPECTION_LIMITS,
): ArchiveInspection {
  const empty: ArchiveInspection = {
    ok: true,
    entryCount: 0,
    totalUncompressedBytes: 0,
    totalCompressedBytes: 0,
  };

  if (!buffer || buffer.length < 22) return empty;

  const isZip =
    buffer.length >= 4 &&
    buffer.slice(0, 4).equals(ZIP_LOCAL_HEADER_SIG);
  if (!isZip) return empty;

  // Locate the first central directory record.
  let offset = buffer.indexOf(ZIP_CENTRAL_DIR_SIG);
  if (offset === -1) {
    // A zip without a central directory is truncated or malformed; the only
    // other legal shape is an empty archive (EOCD only).
    if (buffer.indexOf(ZIP_EOCD_SIG) !== -1) return empty;
    return {
      ...empty,
      ok: false,
      reason: "Malformed archive: missing central directory",
    };
  }

  let entryCount = 0;
  let totalUncompressedBytes = 0;
  let totalCompressedBytes = 0;

  while (offset + 46 <= buffer.length) {
    if (!buffer.slice(offset, offset + 4).equals(ZIP_CENTRAL_DIR_SIG)) break;

    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const filenameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);

    if (compressedSize === ZIP64_MARKER || uncompressedSize === ZIP64_MARKER) {
      return {
        ok: false,
        reason: "Zip64 archives are not permitted",
        entryCount,
        totalUncompressedBytes,
        totalCompressedBytes,
      };
    }

    entryCount += 1;
    totalUncompressedBytes += uncompressedSize;
    totalCompressedBytes += compressedSize;

    if (entryCount > limits.maxEntries) {
      return {
        ok: false,
        reason: `Archive contains more than the permitted ${limits.maxEntries} entries`,
        entryCount,
        totalUncompressedBytes,
        totalCompressedBytes,
      };
    }

    offset += 46 + filenameLength + extraLength + commentLength;
  }

  if (totalUncompressedBytes > limits.maxTotalUncompressedBytes) {
    return {
      ok: false,
      reason: `Archive decompresses to more than the permitted ${limits.maxTotalUncompressedBytes} bytes`,
      entryCount,
      totalUncompressedBytes,
      totalCompressedBytes,
    };
  }

  // Only flag compression ratios once the decompressed size is large enough
  // for the ratio to matter; tiny archives routinely have high ratios.
  const ratio =
    totalUncompressedBytes / Math.max(totalCompressedBytes, 1);
  if (
    totalUncompressedBytes > 1024 * 1024 &&
    ratio > limits.maxCompressionRatio
  ) {
    return {
      ok: false,
      reason: `Archive compression ratio ${Math.round(ratio)}:1 exceeds the permitted ${limits.maxCompressionRatio}:1`,
      entryCount,
      totalUncompressedBytes,
      totalCompressedBytes,
    };
  }

  return {
    ok: true,
    entryCount,
    totalUncompressedBytes,
    totalCompressedBytes,
  };
}

// ---------------------------------------------------------------------------
// Threat scanning
// ---------------------------------------------------------------------------

interface ThreatSignature {
  id: string;
  description: string;
  detect: (buf: Buffer) => boolean;
}

const THREAT_SIGNATURES: ThreatSignature[] = [
  {
    id: "Eicar-Test-Signature",
    description: "EICAR standard antivirus test file",
    detect: (buf) => buf.includes(Buffer.from(EICAR_TEST_STRING, "latin1")),
  },
  {
    id: "Executable-MZ",
    description: "Windows executable header (MZ)",
    detect: (buf) => buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a, // 'MZ'
  },
  {
    id: "Executable-ELF",
    description: "Linux ELF executable header",
    detect: (buf) =>
      buf.length >= 4 &&
      buf[0] === 0x7f &&
      buf.toString("latin1", 1, 4) === "ELF",
  },
  {
    id: "Script-Dangerous-Payload",
    description: "Embedded script with dangerous payload",
    detect: (buf) => {
      const text = buf.toString("latin1");
      const dangerousPatterns = [
        /<script[^>]*>\s*eval\s*\(/i,
        /document\.write\s*\(\s*["']<script/i,
        /powershell\s+(-enc|-e|encodedcommand)/i,
        /cmd\.exe\s+\/c\s+(del|format|reg\s+add)/i,
        /(wscript|cscript)\s+.*\.(vbs|js)/i,
      ];
      return dangerousPatterns.some((re) => re.test(text));
    },
  },
  {
    id: "Pdf-JavaScript",
    description: "PDF with embedded JavaScript action",
    detect: (buf) => {
      if (
        !(buf.length >= 5 && buf.slice(0, 5).toString("latin1") === "%PDF-")
      ) {
        return false;
      }
      const text = buf.toString("latin1");
      return /\/JavaScript\b/i.test(text) || /\/Launch\b/i.test(text);
    },
  },
];

/**
 * Scan a buffer with the embedded signature scanner. This is the fallback
 * engine used when ClamAV is not configured.
 */
export function scanBufferForThreats(buffer: Buffer): {
  threats: string[];
  engine: string;
} {
  const threats: string[] = [];
  for (const sig of THREAT_SIGNATURES) {
    try {
      if (sig.detect(buffer)) threats.push(sig.id);
    } catch {
      // A detection routine must never break the upload pipeline.
    }
  }
  return { threats, engine: HEURISTIC_ENGINE };
}

/**
 * Scan a buffer with ClamAV via the clamd INSTREAM protocol.
 * Returns threats found, or an error if the daemon is unreachable.
 */
export function scanWithClamAV(
  buffer: Buffer,
  timeoutMs: number = CLAMAV_TIMEOUT_MS,
): Promise<{ threats: string[]; engine: string; error?: string }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const CHUNK_SIZE = 1024 * 16;
    const command = Buffer.concat([
      Buffer.from("zINSTREAM\0", "ascii"),
      (() => {
        const parts: Buffer[] = [];
        for (let offset = 0; offset < buffer.length; offset += CHUNK_SIZE) {
          const chunk = buffer.subarray(offset, offset + CHUNK_SIZE);
          const header = Buffer.alloc(4);
          header.writeUInt32BE(chunk.length, 0);
          parts.push(header, chunk);
        }
        const terminator = Buffer.alloc(4);
        parts.push(terminator);
        return Buffer.concat(parts);
      })(),
    ]);

    const socket = connect(CLAMAV_PORT, CLAMAV_HOST);
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({
        threats: [],
        engine: CLAMAV_ENGINE,
        error: "clamav scan timed out",
      });
    }, timeoutMs);

    socket.on("connect", () => socket.write(command));
    socket.on("data", (data) => chunks.push(data));
    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve({
        threats: [],
        engine: CLAMAV_ENGINE,
        error: `clamav unavailable: ${err.message}`,
      });
    });
    socket.on("close", () => {
      clearTimeout(timer);
      const response = Buffer.concat(chunks).toString("utf8");
      const threats = response
        .split("\n")
        .filter((line) => line.toUpperCase().includes("FOUND"))
        .map((line) => line.trim());
      resolve({ threats, engine: CLAMAV_ENGINE });
    });
  });
}

/**
 * Run the full antivirus scan pipeline for an upload.
 *
 * Prefers ClamAV when configured; falls back to the embedded signature
 * scanner. The engine name is recorded so the audit trail shows how a
 * given file was evaluated.
 */
export async function scanFile(
  file: Express.Multer.File,
): Promise<ScanOutcome> {
  const detectedMimetype = sniffMimeType(file.buffer);

  if (CLAMAV_HOST) {
    const clam = await scanWithClamAV(file.buffer);
    if (clam.error) {
      // ClamAV is configured but unreachable – fall back to the embedded
      // scanner so uploads are still gated by *something*.
      const fallback = scanBufferForThreats(file.buffer);
      return {
        status: fallback.threats.length > 0 ? "infected" : "clean",
        threats: fallback.threats,
        engine: `${fallback.engine} (clamav fallback)`,
        detectedMimetype,
        error: clam.error,
      };
    }
    return {
      status: clam.threats.length > 0 ? "infected" : "clean",
      threats: clam.threats,
      engine: clam.engine,
      detectedMimetype,
    };
  }

  const heuristic = scanBufferForThreats(file.buffer);
  return {
    status: heuristic.threats.length > 0 ? "infected" : "clean",
    threats: heuristic.threats,
    engine: heuristic.engine,
    detectedMimetype,
  };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

function mapRecordRow(row: any): UploadSecurityRecord {
  return {
    id: String(row.id),
    userId: row.user_id ?? null,
    originalFilename: row.original_filename,
    storedKey: row.stored_key ?? null,
    declaredMimetype: row.declared_mimetype,
    detectedMimetype: row.detected_mimetype ?? null,
    sha256: row.sha256,
    sizeBytes: Number(row.size_bytes),
    scanStatus: row.scan_status,
    scanEngine: row.scan_engine ?? null,
    threats: row.threats ?? [],
    quarantineUntil: row.quarantine_until
      ? new Date(row.quarantine_until)
      : null,
    scannedAt: row.scanned_at ? new Date(row.scanned_at) : null,
    approvedAt: row.approved_at ? new Date(row.approved_at) : null,
    createdAt: new Date(row.created_at),
  };
}

const RECORD_COLUMNS = `
  id, user_id, original_filename, stored_key, declared_mimetype,
  detected_mimetype, sha256, size_bytes, scan_status, scan_engine,
  threats, quarantine_until, scanned_at, approved_at, created_at
`;

async function insertRecord(params: {
  userId?: string | null;
  originalFilename: string;
  storedKey?: string | null;
  declaredMimetype: string;
  detectedMimetype?: string | null;
  sha256: string;
  sizeBytes: number;
  scanStatus: ScanStatus;
  scanEngine?: string | null;
  threats: string[];
  quarantineUntil?: Date | null;
  scannedAt?: Date | null;
}): Promise<UploadSecurityRecord> {
  const { rows } = await pool.query(
    `INSERT INTO upload_security_records (
       user_id, original_filename, stored_key, declared_mimetype,
       detected_mimetype, sha256, size_bytes, scan_status, scan_engine,
       threats, quarantine_until, scanned_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING ${RECORD_COLUMNS}`,
    [
      params.userId ?? null,
      params.originalFilename,
      params.storedKey ?? null,
      params.declaredMimetype,
      params.detectedMimetype ?? null,
      params.sha256,
      params.sizeBytes,
      params.scanStatus,
      params.scanEngine ?? null,
      params.threats,
      params.quarantineUntil ?? null,
      params.scannedAt ?? null,
    ],
  );
  return mapRecordRow(rows[0]);
}

// ---------------------------------------------------------------------------
// Public upload pipeline
// ---------------------------------------------------------------------------

/**
 * Gate a file upload through the full security pipeline and persist the
 * outcome. This is the entry point used by upload routes.
 *
 * Outcome mapping:
 *   - clean       → file passed scanning; safe to store.
 *   - infected    → threats found; upload must be rejected.
 *   - quarantined → scan engine error / inconclusive; held for the
 *                   quarantine period before it may be approved.
 *   - error       → unexpected failure persisting the record.
 */
export async function gateUpload(
  file: Express.Multer.File,
  options: { userId?: string | null } = {},
): Promise<UploadGateResult> {
  try {
    const sha256 = computeSha256(file.buffer);
    const scan = await scanFile(file);

    if (scan.status === "infected") {
      const record = await insertRecord({
        userId: options.userId,
        originalFilename: file.originalname,
        declaredMimetype: file.mimetype,
        detectedMimetype: scan.detectedMimetype,
        sha256,
        sizeBytes: file.size,
        scanStatus: "infected",
        scanEngine: scan.engine,
        threats: scan.threats,
        scannedAt: new Date(),
      });
      return {
        outcome: "infected",
        record,
        reason: `Upload rejected: malware detected (${scan.threats.join(", ")})`,
      };
    }

    if (scan.error) {
      // Inconclusive scan – hold the upload in quarantine for the
      // configured period instead of silently accepting it.
      const quarantineMinutes =
        Number.isFinite(DEFAULT_QUARANTINE_MINUTES) &&
        DEFAULT_QUARANTINE_MINUTES > 0
          ? DEFAULT_QUARANTINE_MINUTES
          : 1440;
      const quarantineUntil = new Date(
        Date.now() + quarantineMinutes * 60 * 1000,
      );
      const record = await insertRecord({
        userId: options.userId,
        originalFilename: file.originalname,
        declaredMimetype: file.mimetype,
        detectedMimetype: scan.detectedMimetype,
        sha256,
        sizeBytes: file.size,
        scanStatus: "quarantined",
        scanEngine: scan.engine,
        threats: [],
        quarantineUntil,
        scannedAt: new Date(),
      });
      return {
        outcome: "quarantined",
        record,
        reason: `Scan engine unavailable (${scan.engine}); upload quarantined until ${quarantineUntil.toISOString()}`,
      };
    }

    const record = await insertRecord({
      userId: options.userId,
      originalFilename: file.originalname,
      declaredMimetype: file.mimetype,
      detectedMimetype: scan.detectedMimetype,
      sha256,
      sizeBytes: file.size,
      scanStatus: "clean",
      scanEngine: scan.engine,
      threats: [],
      scannedAt: new Date(),
    });
    return { outcome: "clean", record };
  } catch (err) {
    return {
      outcome: "error",
      record: null,
      reason:
        err instanceof Error ? err.message : "Upload security scan failed",
    };
  }
}

/**
 * Attach the stored S3 key to an existing security record once the object
 * has been persisted.
 */
export async function linkStoredKey(
  recordId: string,
  storedKey: string,
): Promise<void> {
  await pool.query(
    `UPDATE upload_security_records
     SET stored_key = $1, updated_at = NOW()
     WHERE id = $2`,
    [storedKey, recordId],
  );
}

/**
 * Fetch a single security record by id.
 */
export async function getUploadSecurityRecord(
  id: string,
): Promise<UploadSecurityRecord | null> {
  const { rows } = await pool.query(
    `SELECT ${RECORD_COLUMNS} FROM upload_security_records WHERE id = $1`,
    [id],
  );
  return rows[0] ? mapRecordRow(rows[0]) : null;
}

/**
 * List quarantine records still awaiting approval (optionally filtered by
 * user). Useful for an admin review queue.
 */
export async function listQuarantinedUploads(
  limit = 100,
  offset = 0,
): Promise<UploadSecurityRecord[]> {
  const { rows } = await pool.query(
    `SELECT ${RECORD_COLUMNS}
     FROM upload_security_records
     WHERE scan_status = 'quarantined'
     ORDER BY created_at DESC
     LIMIT $1 OFFSET $2`,
    [limit, offset],
  );
  return rows.map(mapRecordRow);
}

/**
 * Manually approve a quarantined upload. When a buffer is supplied its
 * integrity is verified against the recorded hash before approval.
 */
export async function approveQuarantinedUpload(
  id: string,
  options: { buffer?: Buffer } = {},
): Promise<{
  success: boolean;
  error?: string;
  record?: UploadSecurityRecord;
}> {
  const record = await getUploadSecurityRecord(id);
  if (!record) return { success: false, error: "Record not found" };
  if (record.scanStatus === "infected") {
    return { success: false, error: "Cannot approve an infected upload" };
  }

  if (options.buffer && !verifyFileIntegrity(options.buffer, record.sha256)) {
    return {
      success: false,
      error: "Integrity check failed: content hash does not match the record",
    };
  }

  const { rows } = await pool.query(
    `UPDATE upload_security_records
     SET scan_status = 'approved', approved_at = NOW(), updated_at = NOW()
     WHERE id = $1
     RETURNING ${RECORD_COLUMNS}`,
    [id],
  );
  return { success: true, record: mapRecordRow(rows[0]) };
}

/**
 * Reject a quarantined or clean upload after manual review.
 */
export async function rejectUpload(
  id: string,
): Promise<{ success: boolean; error?: string }> {
  const result = await pool.query(
    `UPDATE upload_security_records
     SET scan_status = 'rejected', updated_at = NOW()
     WHERE id = $1`,
    [id],
  );
  return { success: (result.rowCount ?? 0) > 0 };
}

/**
 * Auto-release quarantined uploads whose quarantine period has elapsed.
 * Returns the number of records approved. Intended to be called on a
 * schedule (e.g. node-cron) or after admin review.
 */
export async function releaseExpiredQuarantines(): Promise<number> {
  const result = await pool.query(
    `UPDATE upload_security_records
     SET scan_status = 'approved', approved_at = NOW(), updated_at = NOW()
     WHERE scan_status = 'quarantined'
       AND quarantine_until IS NOT NULL
       AND quarantine_until <= NOW()
     RETURNING id`,
  );
  return result.rowCount ?? 0;
}
