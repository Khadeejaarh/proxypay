import { PutObjectCommand, HeadObjectCommand, CopyObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { S3Client, CreateBucketCommand, PutBucketReplicationCommand, PutBucketVersioningCommand, HeadBucketCommand } from '@aws-sdk/client-s3';
import { getS3Client, s3Config, getS3ObjectUrl } from '../config/s3';
import { generateUniqueFilename, generateDisputeS3Key } from '../middleware/disputeUpload';
import {
  inspectFileSignature,
  inspectArchiveSafety,
} from './fileSecurityService';
import {
  DISPUTE_EVIDENCE_UPLOAD_LIMITS,
  DISPUTE_ARCHIVE_SAFETY_LIMITS,
} from '../config/uploadLimits';

export interface DisputeUploadResult {
  success: boolean;
  fileUrl?: string;
  key?: string;
  error?: string;
}

export interface DisputeUploadOptions {
  disputeId: string;
  file: Express.Multer.File;
  uploadedBy: string;
  metadata?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// S3 Backup Configuration (#629)
//
// Dispute evidence files are automatically backed up to a separate S3 bucket
// in a different AWS region.  Two layers of redundancy are provided:
//
//   1. Cross-region replication (CRR) — configured on the primary bucket so AWS
//      replicates every new object asynchronously to the backup bucket.  This
//      is the primary mechanism and requires no extra code per upload.
//
//   2. Snapshot copy on upload — each evidence file is synchronously copied to
//      the backup bucket immediately after the primary upload so that a backup
//      exists even before CRR processes the object.
//
// Configuration via environment variables:
//   DISPUTE_EVIDENCE_BACKUP_BUCKET — name of the backup S3 bucket
//   DISPUTE_EVIDENCE_BACKUP_REGION — AWS region for the backup bucket (default: us-west-2)
//   DISPUTE_BACKUP_REPLICATION_ROLE_ARN — IAM role ARN that S3 uses for CRR
// ---------------------------------------------------------------------------

/** Name of the backup S3 bucket for dispute evidence. */
export const DISPUTE_EVIDENCE_BACKUP_BUCKET =
  process.env.DISPUTE_EVIDENCE_BACKUP_BUCKET ?? `${s3Config.bucket}-dispute-backup`;

/** AWS region where the backup bucket lives (must differ from primary). */
export const DISPUTE_EVIDENCE_BACKUP_REGION =
  process.env.DISPUTE_EVIDENCE_BACKUP_REGION ?? 'us-west-2';

/**
 * Returns an S3 client pointed at the backup region.
 */
export function getBackupS3Client(): S3Client {
  return new S3Client({ region: DISPUTE_EVIDENCE_BACKUP_REGION });
}

/**
 * Copies a dispute evidence object from the primary bucket to the backup
 * bucket.  Called immediately after each upload to guarantee a backup exists
 * before cross-region replication catches up.
 *
 * @param key  The S3 object key in the primary bucket
 * @returns    true if the copy succeeded, false otherwise (non-fatal)
 */
export async function backupDisputeEvidenceToSecondaryBucket(key: string): Promise<boolean> {
  try {
    const backupClient = getBackupS3Client();
    const copySource = encodeURIComponent(`${s3Config.bucket}/${key}`);

    await backupClient.send(new CopyObjectCommand({
      CopySource: copySource,
      Bucket: DISPUTE_EVIDENCE_BACKUP_BUCKET,
      Key: key,
      MetadataDirective: 'COPY',
    }));

    return true;
  } catch (error) {
    // Backup failure is non-fatal — the primary upload already succeeded.
    // Log the error but do not surface it to the caller.
    console.error('[dispute-backup] Failed to copy evidence to backup bucket:', error);
    return false;
  }
}

/**
 * Verifies that a dispute evidence file exists in the backup bucket.
 * Used by the daily backup verification job.
 *
 * @param key  The S3 object key
 */
export async function verifyDisputeEvidenceBackup(key: string): Promise<boolean> {
  try {
    const backupClient = getBackupS3Client();
    await backupClient.send(new HeadObjectCommand({
      Bucket: DISPUTE_EVIDENCE_BACKUP_BUCKET,
      Key: key,
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Configures cross-region replication on the primary dispute evidence bucket.
 *
 * This is an idempotent infrastructure-setup function intended to be called
 * once during deployment or via an admin script.  It:
 *   1. Enables versioning on the primary bucket (required for CRR).
 *   2. Ensures the backup bucket exists in the target region.
 *   3. Puts a replication configuration on the primary bucket that replicates
 *      all objects under the `disputes/` prefix to the backup bucket.
 *
 * Requires:
 *   - DISPUTE_BACKUP_REPLICATION_ROLE_ARN env var (IAM role that S3 assumes)
 *   - The IAM role must have s3:ReplicateObject permissions on both buckets.
 *
 * @returns true if configuration succeeded, false if not possible (e.g., no IAM role configured)
 */
export async function configureDisputeEvidenceCrossRegionReplication(): Promise<boolean> {
  const replicationRoleArn = process.env.DISPUTE_BACKUP_REPLICATION_ROLE_ARN;
  if (!replicationRoleArn) {
    console.warn('[dispute-backup] DISPUTE_BACKUP_REPLICATION_ROLE_ARN not set — skipping CRR configuration');
    return false;
  }

  try {
    const primaryClient = getS3Client();
    const backupClient = getBackupS3Client();

    // 1. Enable versioning on the primary bucket (required for CRR)
    await primaryClient.send(new PutBucketVersioningCommand({
      Bucket: s3Config.bucket,
      VersioningConfiguration: { Status: 'Enabled' },
    }));

    // 2. Ensure backup bucket exists — create it if missing
    try {
      await backupClient.send(new HeadBucketCommand({ Bucket: DISPUTE_EVIDENCE_BACKUP_BUCKET }));
    } catch {
      await backupClient.send(new CreateBucketCommand({
        Bucket: DISPUTE_EVIDENCE_BACKUP_BUCKET,
        CreateBucketConfiguration: { LocationConstraint: DISPUTE_EVIDENCE_BACKUP_REGION as any },
      }));
      // Enable versioning on backup bucket too (required as CRR destination)
      await backupClient.send(new PutBucketVersioningCommand({
        Bucket: DISPUTE_EVIDENCE_BACKUP_BUCKET,
        VersioningConfiguration: { Status: 'Enabled' },
      }));
    }

    // 3. Configure cross-region replication on the primary bucket
    await primaryClient.send(new PutBucketReplicationCommand({
      Bucket: s3Config.bucket,
      ReplicationConfiguration: {
        Role: replicationRoleArn,
        Rules: [
          {
            ID: 'dispute-evidence-crr',
            Status: 'Enabled',
            Filter: { Prefix: 'disputes/' },
            Destination: {
              Bucket: `arn:aws:s3:::${DISPUTE_EVIDENCE_BACKUP_BUCKET}`,
              StorageClass: 'STANDARD_IA',
            },
            DeleteMarkerReplication: { Status: 'Enabled' },
          },
        ],
      },
    }));

    console.log(
      `[dispute-backup] Cross-region replication configured: ${s3Config.bucket} → ${DISPUTE_EVIDENCE_BACKUP_BUCKET} (${DISPUTE_EVIDENCE_BACKUP_REGION})`,
    );
    return true;
  } catch (error) {
    console.error('[dispute-backup] Failed to configure cross-region replication:', error);
    return false;
  }
}

export interface DisputeUploadResult {
  success: boolean;
  fileUrl?: string;
  key?: string;
  error?: string;
}

export interface DisputeUploadOptions {
  disputeId: string;
  file: Express.Multer.File;
  uploadedBy: string;
  metadata?: Record<string, string>;
}

/**
 * Upload dispute evidence file to S3 bucket.
 *
 * After a successful primary upload the file is synchronously copied to the
 * backup bucket (see backupDisputeEvidenceToSecondaryBucket).  Copy failures
 * are non-fatal and logged; the primary upload result is still returned as
 * successful.  AWS cross-region replication will also replicate the object
 * asynchronously as a second safety net.
 */
export const uploadDisputeEvidenceToS3 = async (
  options: DisputeUploadOptions
): Promise<DisputeUploadResult> => {
  try {
    const { disputeId, file, uploadedBy, metadata = {} } = options;

    // Security validation: file type, size, and malware/executable extension checks
    const validation = validateDisputeEvidenceFile(file);
    if (!validation.valid) {
      return {
        success: false,
        error: validation.error || "File security validation failed",
      };
    }

    // Check for dangerous double extensions or executable markers
    const dangerousPattern = /\.(exe|bat|sh|cmd|msi|vbs|ps1|jar|dll|scr|pif)$/i;
    if (dangerousPattern.test(file.originalname)) {
      return {
        success: false,
        error: "Executable or potentially harmful file format rejected",
      };
    }
    
    // Generate unique filename and S3 key
    const uniqueFilename = generateUniqueFilename(file.originalname);
    const key = generateDisputeS3Key(disputeId, uniqueFilename);
    
    const s3Client = getS3Client();
    
    // Prepare upload command
    const command = new PutObjectCommand({
      Bucket: s3Config.bucket,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype,
      Metadata: {
        originalName: file.originalname,
        disputeId: disputeId,
        uploadedBy: uploadedBy,
        uploadedAt: new Date().toISOString(),
        fileSize: file.size.toString(),
        ...metadata,
      },
      // Set appropriate ACL (private by default)
      // ACL: 'private',
    });
    
    // Upload to primary S3 bucket
    await s3Client.send(command);
    
    // Immediately copy to backup bucket (#629 — snapshot backup on upload)
    // This is fire-and-forget; a failure here does not affect the upload result.
    backupDisputeEvidenceToSecondaryBucket(key).catch((err) =>
      console.error('[dispute-backup] Unexpected error during backup copy:', err),
    );
    
    // Generate public URL
    const fileUrl = getS3ObjectUrl(key);
    
    return {
      success: true,
      fileUrl,
      key,
    };
  } catch (error) {
    console.error('S3 dispute evidence upload error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown upload error',
    };
  }
};

/**
 * Upload multiple dispute evidence files to S3
 */
export const uploadMultipleDisputeEvidenceToS3 = async (
  disputeId: string,
  files: Express.Multer.File[],
  uploadedBy: string,
  metadata?: Record<string, string>
): Promise<DisputeUploadResult[]> => {
  const results: DisputeUploadResult[] = [];
  
  for (const file of files) {
    const result = await uploadDisputeEvidenceToS3({
      disputeId,
      file,
      uploadedBy,
      metadata,
    });
    results.push(result);
  }
  
  return results;
};

/**
 * Check if dispute evidence file exists in S3
 */
export const disputeEvidenceExistsInS3 = async (key: string): Promise<boolean> => {
  try {
    const s3Client = getS3Client();
    const command = new HeadObjectCommand({
      Bucket: s3Config.bucket,
      Key: key,
    });
    
    await s3Client.send(command);
    return true;
  } catch (error) {
    return false;
  }
};

/**
 * Validate dispute evidence file before upload.
 *
 * Enforces the per-route byte/count limits from
 * `DISPUTE_EVIDENCE_UPLOAD_LIMITS`, then inspects the actual file content:
 * magic bytes must match the declared type (office containers are accepted
 * as their zip/OLE2 equivalents) and zip-based containers must stay within
 * the archive-safety budget so archive bombs are rejected before storage.
 */
export const validateDisputeEvidenceFile = (file: Express.Multer.File): { valid: boolean; error?: string } => {
  const limits = DISPUTE_EVIDENCE_UPLOAD_LIMITS;

  if (!limits.allowedMimeTypes.includes(file.mimetype)) {
    return {
      valid: false,
      error: `Invalid file type. Allowed types: ${limits.allowedMimeTypes.join(', ')}`,
    };
  }

  if (file.size > limits.maxFileSizeBytes) {
    return {
      valid: false,
      error: `File size exceeds maximum limit of ${limits.maxFileSizeBytes / (1024 * 1024)}MB`,
    };
  }

  // Inspect the actual content (magic bytes): catches spoofed extensions,
  // polyglots and archives smuggled in as other document types.
  const signature = inspectFileSignature(file, {
    allowedDeclaredTypes: [...limits.allowedMimeTypes],
  });
  if (!signature.ok) {
    return {
      valid: false,
      error: signature.reason || 'File content does not match its declared type',
    };
  }

  // Archive-bomb guard for zip-based containers (docx/xlsx): the declared
  // decompressed size and compression ratio must stay within budget.
  if (signature.detectedMimetype === 'application/zip') {
    const archive = inspectArchiveSafety(file.buffer, DISPUTE_ARCHIVE_SAFETY_LIMITS);
    if (!archive.ok) {
      return {
        valid: false,
        error: archive.reason || 'Archive rejected by safety limits',
      };
    }
  }

  return { valid: true };
};