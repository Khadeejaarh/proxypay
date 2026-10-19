import { createHash } from 'crypto';

export type ParameterClassification =
  | 'public'
  | 'pii'
  | 'credential'
  | 'sensitive';

export interface ParameterPolicy {
  /** Classification applied to a parameter when no field-specific rule matches. */
  defaultClassification: ParameterClassification;
  /** Field-name (case-insensitive) to classification overrides, applied recursively. */
  fieldRules: Record<string, ParameterClassification>;
}

export interface ClassifiedParameter {
  classification: ParameterClassification;
  /** Present only for non-sensitive classifications; never contains raw PII/credentials. */
  value?: unknown;
}

export interface SlowQueryLogEntry {
  fingerprint: string;
  durationMs: number;
  parameters: ClassifiedParameter[];
}

const DEFAULT_POLICY: ParameterPolicy = {
  defaultClassification: 'public',
  fieldRules: {
    password: 'credential',
    passwd: 'credential',
    secret: 'credential',
    token: 'credential',
    apikey: 'credential',
    api_key: 'credential',
    authorization: 'credential',
    email: 'pii',
    phone: 'pii',
    ssn: 'pii',
    name: 'pii',
    address: 'pii',
    dob: 'pii',
  },
};

/**
 * Normalizes SQL into a stable fingerprint so logs never carry literal values.
 */
export function fingerprintSql(sql: string): string {
  const normalized = sql
    .replace(/'(?:[^']|'')*'/g, '?')
    .replace(/\b\d+(?:\.\d+)?\b/g, '?')
    .replace(/\s+/g, ' ')
    .trim();
  return createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

function classifyValue(value: unknown, policy: ParameterPolicy, fieldName?: string): ParameterClassification {
  if (fieldName) {
    const rule = policy.fieldRules[fieldName.toLowerCase()];
    if (rule) {
      return rule;
    }
  }
  if (value !== null && typeof value === 'object') {
    // Nested structures are treated as sensitive unless every leaf is public.
    const leaves = collectLeaves(value, policy);
    if (leaves.some((c) => c !== 'public')) {
      return 'sensitive';
    }
  }
  return policy.defaultClassification;
}

function collectLeaves(value: unknown, policy: ParameterPolicy): ParameterClassification[] {
  if (value === null || typeof value !== 'object') {
    return [policy.defaultClassification];
  }
  const out: ParameterClassification[] = [];
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const rule = policy.fieldRules[key.toLowerCase()];
    if (rule) {
      out.push(rule);
    } else {
      out.push(...collectLeaves(child, policy));
    }
  }
  return out;
}

/**
 * Classifies a parameter list, stripping raw values for any non-public classification.
 */
export function classifyParameters(
  params: unknown[],
  policy: ParameterPolicy = DEFAULT_POLICY,
): ClassifiedParameter[] {
  return params.map((param) => {
    const classification = classifyValue(param, policy);
    if (classification === 'public') {
      return { classification, value: param };
    }
    return { classification };
  });
}

/**
 * Builds a slow-query log entry containing only the SQL fingerprint and
 * per-parameter classifications — never raw PII or credential contents.
 */
export function buildSlowQueryLogEntry(
  sql: string,
  params: unknown[],
  durationMs: number,
  policy: ParameterPolicy = DEFAULT_POLICY,
): SlowQueryLogEntry {
  return {
    fingerprint: fingerprintSql(sql),
    durationMs,
    parameters: classifyParameters(params, policy),
  };
}

export function logSlowQuery(
  sql: string,
  params: unknown[],
  durationMs: number,
  policy: ParameterPolicy = DEFAULT_POLICY,
): void {
  const entry = buildSlowQueryLogEntry(sql, params, durationMs, policy);
  console.warn('[slow-query]', JSON.stringify(entry));
}
