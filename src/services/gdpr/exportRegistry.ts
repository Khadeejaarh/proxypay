/**
 * GDPR data subject export registry.
 *
 * Every table that stores personal data linked to a data subject MUST be
 * classified here as one of:
 *   - "export":    included in the data subject export (with the query used)
 *   - "exclusion": deliberately excluded, with a documented rationale
 *   - "retention": not exported but retained under a documented rationale
 *
 * The completeness check (see `verifyExportCompleteness`) queries the
 * PostgreSQL catalog for user-linked tables and fails when a personal-data
 * table is missing from this registry. This guards against new user-linked
 * tables being silently omitted as the schema evolves.
 */

export type ExportClassification = "export" | "exclusion" | "retention";

export interface ExportRegistryEntry {
  /** Table name (schema-qualified or bare). */
  table: string;
  classification: ExportClassification;
  /** Human-readable rationale; required for exclusion/retention. */
  rationale: string;
  /** For "export" entries: the columns surfaced in the export. */
  columns?: string[];
}

/**
 * Explicit registry of personal-data tables and how each is handled in the
 * data subject export. Covers profile, transaction, dispute, KYC, audit, and
 * webhook data.
 */
export const EXPORT_REGISTRY: readonly ExportRegistryEntry[] = [
  // Profile data
  {
    table: "users",
    classification: "export",
    rationale: "Core profile record for the data subject.",
    columns: ["id", "email", "name", "created_at", "updated_at"],
  },
  {
    table: "user_profiles",
    classification: "export",
    rationale: "Extended profile attributes belonging to the data subject.",
    columns: ["user_id", "display_name", "locale", "timezone"],
  },
  {
    table: "user_sessions",
    classification: "retention",
    rationale:
      "Session records are security-sensitive and retained for fraud/abuse " +
      "investigation; not part of the subject export.",
  },

  // Transaction data
  {
    table: "transactions",
    classification: "export",
    rationale: "Financial transactions initiated by the data subject.",
    columns: ["id", "user_id", "amount", "currency", "status", "created_at"],
  },
  {
    table: "transaction_events",
    classification: "export",
    rationale: "State transitions for the subject's transactions.",
    columns: ["id", "transaction_id", "event_type", "created_at"],
  },

  // Dispute data
  {
    table: "disputes",
    classification: "export",
    rationale: "Disputes opened by or against the data subject.",
    columns: ["id", "user_id", "transaction_id", "status", "reason", "created_at"],
  },
  {
    table: "dispute_messages",
    classification: "export",
    rationale: "Messages authored by the data subject within disputes.",
    columns: ["id", "dispute_id", "author_id", "body", "created_at"],
  },

  // KYC data
  {
    table: "kyc_verifications",
    classification: "export",
    rationale: "Identity verification records for the data subject.",
    columns: ["id", "user_id", "status", "provider", "created_at"],
  },
  {
    table: "kyc_documents",
    classification: "retention",
    rationale:
      "Raw identity documents are retained under AML/KYC legal obligations " +
      "and are not included in the export payload; metadata is exported via " +
      "kyc_verifications.",
  },

  // Audit data
  {
    table: "audit_logs",
    classification: "export",
    rationale: "Audit entries attributable to the data subject.",
    columns: ["id", "actor_id", "action", "target", "created_at"],
  },

  // Webhook data
  {
    table: "webhook_endpoints",
    classification: "export",
    rationale: "Webhook endpoints configured by the data subject.",
    columns: ["id", "user_id", "url", "created_at"],
  },
  {
    table: "webhook_deliveries",
    classification: "export",
    rationale: "Delivery attempts for the subject's webhook endpoints.",
    columns: ["id", "endpoint_id", "status", "created_at"],
  },
];

/**
 * Minimal query interface so the check can run against a real pg client or a
 * test double without pulling in a driver dependency here.
 */
export interface CatalogQueryable {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[] }>;
}

/**
 * Catalog query returning tables that appear to hold user-linked personal
 * data: any table with a column referencing `users` (directly or via a
 * `user_id`/`actor_id`/`author_id` foreign key) or named like a user table.
 */
export const USER_LINKED_TABLES_SQL = `
  SELECT DISTINCT c.conrelid::regclass::text AS table_name
  FROM pg_constraint c
  JOIN pg_class t ON t.oid = c.conrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
  JOIN pg_class rt ON rt.oid = c.confrelid
  WHERE c.contype = 'f'
    AND rt.relname = 'users'
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  UNION
  SELECT DISTINCT t.relname AS table_name
  FROM pg_class t
  JOIN pg_namespace n ON n.oid = t.relnamespace
  JOIN pg_attribute a ON a.attrelid = t.oid
  WHERE t.relkind = 'r'
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND a.attname IN ('user_id', 'actor_id', 'author_id')
    AND NOT a.attisdropped
`;

export interface CompletenessResult {
  ok: boolean;
  /** Personal-data tables found in the catalog but missing from the registry. */
  missing: string[];
}

/**
 * Verify that every user-linked personal-data table in the database is
 * classified in the export registry. Returns `ok: false` with the offending
 * tables when any table lacks an export, exclusion, or retention rationale.
 */
export async function verifyExportCompleteness(
  db: CatalogQueryable,
): Promise<CompletenessResult> {
  const { rows } = await db.query<{ table_name: string }>(
    USER_LINKED_TABLES_SQL,
  );

  const registered = new Set(
    EXPORT_REGISTRY.map((entry) => normalizeTableName(entry.table)),
  );

  const missing = rows
    .map((row) => normalizeTableName(row.table_name))
    .filter((table) => table.length > 0 && !registered.has(table));

  return { ok: missing.length === 0, missing };
}

function normalizeTableName(name: string): string {
  // Strip schema qualification and quoting so catalog output matches registry
  // entries regardless of how the table is referenced.
  const bare = name.includes(".") ? name.split(".").pop()! : name;
  return bare.replace(/"/g, "").trim();
}
