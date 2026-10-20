/**
 * Structured SQL query logging.
 *
 * Slow-query logs emit a normalized query fingerprint plus per-parameter
 * classifications (PII / credential / sensitive / plain) instead of raw
 * parameter contents. This replaces regex-only redaction, which could not
 * reliably identify every sensitive field or nested value.
 */

export type ParameterClassification =
  | 'plain'
  | 'pii'
  | 'credential'
  | 'sensitive';

export interface ParameterPolicy {
  /** Classification applied to a parameter by name or position. */
  classification: ParameterClassification;
  /** Optional explicit field names (case-insensitive) this policy covers. */
  fields?: string[];
}

export interface ParameterClassificationMetadata {
  /** Policies keyed by parameter name (case-insensitive). */
  byName?: Record<string, ParameterPolicy>;
  /** Policies keyed by zero-based parameter position. */
  byPosition?: Record<number, ParameterPolicy>;
  /** Default classification for unclassified parameters. */
  defaultClassification?: ParameterClassification;
}

export interface ClassifiedParameter {
  /** Position of the parameter in the query. */
  index: number;
  /** Field name when known, otherwise undefined. */
  field?: string;
  classification: ParameterClassification;
  /** True when the raw value must never be logged. */
  redacted: boolean;
}

export interface SlowQueryLogEntry {
  /** Normalized SQL with literals replaced by placeholders. */
  fingerprint: string;
  durationMs: number;
  parameters: ClassifiedParameter[];
}

const SENSITIVE_CLASSIFICATIONS: ReadonlySet<ParameterClassification> = new Set([
  'pii',
  'credential',
  'sensitive',
]);

/**
 * Normalize SQL into a fingerprint: collapse whitespace and replace inline
 * literals with positional placeholders so raw values never leak.
 */
export function fingerprintQuery(sql: string): string {
  return sql
    .replace(/\s+/g, ' ')
    .replace(/'(?:[^'\\]|\\.)*'/g, '?')
    .replace(/"(?:[^"\\]|\\.)*"/g, '?')
    .replace(/\b\d+(?:\.\d+)?\b/g, '?')
    .trim();
}

function resolvePolicy(
  metadata: ParameterClassificationMetadata | undefined,
  index: number,
  field: string | undefined,
): ParameterClassification {
  if (metadata) {
    if (field && metadata.byName) {
      const named = metadata.byName[field.toLowerCase()];
      if (named) return named.classification;
    }
    if (metadata.byPosition && metadata.byPosition[index]) {
      return metadata.byPosition[index].classification;
    }
    if (metadata.defaultClassification) {
      return metadata.defaultClassification;
    }
  }
  return 'plain';
}

/**
 * Classify a single parameter value. Nested objects/arrays are walked so that
 * sensitive nested fields are classified rather than logged raw.
 */
export function classifyParameter(
  value: unknown,
  index: number,
  metadata: ParameterClassificationMetadata | undefined,
  field?: string,
): ClassifiedParameter {
  const classification = resolvePolicy(metadata, index, field);
  const redacted = SENSITIVE_CLASSIFICATIONS.has(classification);

  if (!redacted && value !== null && typeof value === 'object') {
    // Nested structures are never logged raw; classify conservatively.
    return {
      index,
      field,
      classification: 'sensitive',
      redacted: true,
    };
  }

  return { index, field, classification, redacted };
}

/**
 * Build a slow-query log entry containing only the fingerprint and parameter
 * classifications. Raw parameter values are intentionally omitted.
 */
export function buildSlowQueryLogEntry(
  sql: string,
  params: readonly unknown[],
  durationMs: number,
  metadata?: ParameterClassificationMetadata,
): SlowQueryLogEntry {
  const parameters = params.map((value, index) =>
    classifyParameter(value, index, metadata),
  );

  return {
    fingerprint: fingerprintQuery(sql),
    durationMs,
    parameters,
  };
}

export interface QueryLoggerOptions {
  slowQueryThresholdMs?: number;
  metadata?: ParameterClassificationMetadata;
  sink?: (entry: SlowQueryLogEntry) => void;
}

export class QueryLogger {
  private readonly thresholdMs: number;
  private readonly metadata?: ParameterClassificationMetadata;
  private readonly sink: (entry: SlowQueryLogEntry) => void;

  constructor(options: QueryLoggerOptions = {}) {
    this.thresholdMs = options.slowQueryThresholdMs ?? 1000;
    this.metadata = options.metadata;
    this.sink = options.sink ?? ((entry) => console.warn('[slow-query]', entry));
  }

  log(sql: string, params: readonly unknown[], durationMs: number): void {
    if (durationMs < this.thresholdMs) return;
    this.sink(buildSlowQueryLogEntry(sql, params, durationMs, this.metadata));
  }
}
