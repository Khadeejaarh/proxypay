/**
 * GDPR data subject export.
 *
 * Selects a defined set of profile, transaction, dispute, KYC, audit, and
 * webhook data for a data subject. New user-linked tables can be omitted as
 * the schema evolves, so this module also maintains an explicit export
 * registry and a completeness check that fails when a personal-data table has
 * no export, exclusion, or documented retention rationale.
 */

export type ExportClassification = 'export' | 'exclusion' | 'retention';

export interface ExportRegistryEntry {
  /** Table name as it appears in the PostgreSQL catalog. */
  table: string;
  classification: ExportClassification;
  /** Human-readable rationale for the classification. */
  rationale: string;
}

/**
 * Explicit registry of every table that holds personal data linked to a data
 * subject. Each entry must be classified as exported, excluded, or retained
 * with a documented rationale.
 */
export const EXPORT_REGISTRY: readonly ExportRegistryEntry[] = [
  {
    table: 'users',
    classification: 'export',
    rationale: 'Core profile data included in the data subject export.',
  },
  {
    table: 'user_profiles',
    classification: 'export',
    rationale: 'Extended profile data included in the data subject export.',
  },
  {
    table: 'transactions',
    classification: 'export',
    rationale: 'Transaction history included in the data subject export.',
  },
  {
    table: 'disputes',
    classification: 'export',
    rationale: 'Dispute records included in the data subject export.',
  },
  {
    table: 'kyc_verifications',
    classification: 'export',
    rationale: 'KYC verification records included in the data subject export.',
  },
  {
    table: 'audit_logs',
    classification: 'export',
    rationale: 'Audit entries attributable to the subject are exported.',
  },
  {
    table: 'webhook_events',
    classification: 'export',
    rationale: 'Webhook events linked to the subject are exported.',
  },
  {
    table: 'sessions',
    classification: 'exclusion',
    rationale:
      'Ephemeral session tokens are not personal data of enduring value and are excluded.',
  },
  {
    table: 'password_reset_tokens',
    classification: 'exclusion',
    rationale:
      'Single-use security tokens are excluded to avoid leaking credentials.',
  },
  {
    table: 'legal_holds',
    classification: 'retention',
    rationale:
      'Retained under legal obligation; not exported while a hold is active.',
  },
];

/**
 * Tables that are known to hold personal data and therefore must appear in the
 * export registry. Kept explicit so the completeness check can detect new
 * user-linked tables that were added to the schema without a classification.
 */
export const PERSONAL_DATA_TABLES: readonly string[] = [
  'users',
  'user_profiles',
  'transactions',
  'disputes',
  'kyc_verifications',
  'audit_logs',
  'webhook_events',
  'sessions',
  'password_reset_tokens',
  'legal_holds',
];

export interface CompletenessViolation {
  table: string;
  reason: string;
}

/**
 * Verify that every personal-data table has an export, exclusion, or
 * documented retention rationale in the export registry.
 */
export function verifyExportCompleteness(
  registry: readonly ExportRegistryEntry[] = EXPORT_REGISTRY,
  personalDataTables: readonly string[] = PERSONAL_DATA_TABLES,
): CompletenessViolation[] {
  const violations: CompletenessViolation[] = [];
  const byTable = new Map<string, ExportRegistryEntry>();

  for (const entry of registry) {
    if (byTable.has(entry.table)) {
      violations.push({
        table: entry.table,
        reason: 'Duplicate export registry entry.',
      });
      continue;
    }
    byTable.set(entry.table, entry);
  }

  for (const table of personalDataTables) {
    const entry = byTable.get(table);
    if (!entry) {
      violations.push({
        table,
        reason:
          'Personal-data table has no export, exclusion, or retention rationale.',
      });
      continue;
    }
    if (!entry.rationale || entry.rationale.trim().length === 0) {
      violations.push({
        table,
        reason: 'Export registry entry is missing a documented rationale.',
      });
    }
  }

  return violations;
}

/**
 * Query used to discover user-linked tables from the PostgreSQL catalog. The
 * result should be reconciled against PERSONAL_DATA_TABLES so newly added
 * personal-data tables are caught by the completeness check.
 */
export const PERSONAL_DATA_TABLES_CATALOG_QUERY = `
  SELECT c.table_name
  FROM information_schema.columns c
  WHERE c.table_schema = 'public'
    AND c.column_name IN ('user_id', 'subject_id', 'owner_id')
  ORDER BY c.table_name
`;

export interface DataSubjectExport {
  profile: unknown;
  transactions: unknown[];
  disputes: unknown[];
  kyc: unknown[];
  audit: unknown[];
  webhooks: unknown[];
}

export interface DataSubjectExportDeps {
  loadProfile: (subjectId: string) => Promise<unknown>;
  loadTransactions: (subjectId: string) => Promise<unknown[]>;
  loadDisputes: (subjectId: string) => Promise<unknown[]>;
  loadKyc: (subjectId: string) => Promise<unknown[]>;
  loadAudit: (subjectId: string) => Promise<unknown[]>;
  loadWebhooks: (subjectId: string) => Promise<unknown[]>;
}

/**
 * Build a data subject export covering profile, transaction, dispute, KYC,
 * audit, and webhook data.
 */
export async function buildDataSubjectExport(
  subjectId: string,
  deps: DataSubjectExportDeps,
): Promise<DataSubjectExport> {
  const [profile, transactions, disputes, kyc, audit, webhooks] =
    await Promise.all([
      deps.loadProfile(subjectId),
      deps.loadTransactions(subjectId),
      deps.loadDisputes(subjectId),
      deps.loadKyc(subjectId),
      deps.loadAudit(subjectId),
      deps.loadWebhooks(subjectId),
    ]);

  return { profile, transactions, disputes, kyc, audit, webhooks };
}
