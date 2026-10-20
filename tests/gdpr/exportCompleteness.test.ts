import { describe, it, expect } from 'vitest';
import { Client } from 'pg';

/**
 * Issue #782: Verify completeness of data subject exports.
 *
 * The GDPR export selects a defined set of profile, transaction, dispute,
 * KYC, audit, and webhook data. New user-linked tables can silently be
 * omitted as the schema evolves. This test maintains an explicit export
 * registry and fails when a personal-data table in the database lacks an
 * export, an exclusion, or a documented retention rationale.
 */

type Classification =
  | { kind: 'export'; exporter: string }
  | { kind: 'exclusion'; rationale: string }
  | { kind: 'retention'; rationale: string };

/**
 * Explicit export registry. Every personal-data table must appear here with
 * either an exporter, a documented exclusion, or a documented retention
 * rationale. Keys are table names in the public schema.
 */
const EXPORT_REGISTRY: Record<string, Classification> = {
  // Profile data
  users: { kind: 'export', exporter: 'exportProfile' },
  user_profiles: { kind: 'export', exporter: 'exportProfile' },
  user_addresses: { kind: 'export', exporter: 'exportProfile' },
  user_settings: { kind: 'export', exporter: 'exportProfile' },

  // Transaction data
  transactions: { kind: 'export', exporter: 'exportTransactions' },
  transaction_items: { kind: 'export', exporter: 'exportTransactions' },
  payment_methods: { kind: 'export', exporter: 'exportTransactions' },

  // Dispute data
  disputes: { kind: 'export', exporter: 'exportDisputes' },
  dispute_messages: { kind: 'export', exporter: 'exportDisputes' },
  dispute_evidence: { kind: 'export', exporter: 'exportDisputes' },

  // KYC data
  kyc_verifications: { kind: 'export', exporter: 'exportKyc' },
  kyc_documents: { kind: 'export', exporter: 'exportKyc' },

  // Audit data
  audit_logs: { kind: 'export', exporter: 'exportAudit' },

  // Webhook data
  webhook_endpoints: { kind: 'export', exporter: 'exportWebhooks' },
  webhook_deliveries: { kind: 'export', exporter: 'exportWebhooks' },

  // Documented exclusions / retention rationales
  sessions: {
    kind: 'exclusion',
    rationale: 'Ephemeral auth sessions; not personal data retained for export.',
  },
  schema_migrations: {
    kind: 'exclusion',
    rationale: 'Internal migration bookkeeping; contains no personal data.',
  },
  deletion_outbox: {
    kind: 'retention',
    rationale:
      'Deletion outbox holds only identifiers pending erasure; retained for audit of deletion, not exported.',
  },
};

/**
 * Columns that indicate a table is linked to a user / subject and therefore
 * carries personal data requiring an export decision.
 */
const PERSONAL_DATA_COLUMNS = ['user_id', 'subject_id', 'customer_id', 'owner_id'];

async function fetchPersonalDataTables(client: Client): Promise<string[]> {
  const { rows } = await client.query<{ table_name: string }>(
    `SELECT DISTINCT c.table_name
       FROM information_schema.columns c
       JOIN information_schema.tables t
         ON t.table_schema = c.table_schema
        AND t.table_name = c.table_name
      WHERE c.table_schema = 'public'
        AND t.table_type = 'BASE TABLE'
        AND c.column_name = ANY($1::text[])
      ORDER BY c.table_name`,
    [PERSONAL_DATA_COLUMNS],
  );
  return rows.map((r) => r.table_name);
}

describe('GDPR export completeness (#782)', () => {
  it('every personal-data table has an export, exclusion, or retention rationale', async () => {
    const client = new Client({ connectionString: process.env.DATABASE_URL });
    await client.connect();
    try {
      const personalDataTables = await fetchPersonalDataTables(client);
      const missing = personalDataTables.filter((t) => !(t in EXPORT_REGISTRY));

      expect(
        missing,
        `Personal-data tables missing from the export registry: ${missing.join(', ')}. ` +
          'Add an export, exclusion, or documented retention rationale in EXPORT_REGISTRY.',
      ).toEqual([]);
    } finally {
      await client.end();
    }
  });

  it('registry entries are well-formed', () => {
    for (const [table, entry] of Object.entries(EXPORT_REGISTRY)) {
      if (entry.kind === 'export') {
        expect(entry.exporter, `exporter for ${table}`).toBeTruthy();
      } else {
        expect(entry.rationale, `rationale for ${table}`).toBeTruthy();
      }
    }
  });
});
