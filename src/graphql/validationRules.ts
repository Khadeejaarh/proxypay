/**
 * Shared GraphQL validation rules (issue #813).
 *
 * Depth and complexity limits are defined once and applied to BOTH surfaces:
 *   - HTTP       → ApolloServer validationRules (src/graphql/server.ts)
 *   - WebSocket  → graphql-ws validationRules + per-message complexity check
 *                  in onSubscribe (src/graphql/server.ts)
 *
 * Budgets are configurable via env so operators can tune them without a
 * redeploy:
 *   - GRAPHQL_MAX_DEPTH                        (default 5)
 *   - GRAPHQL_MAX_COMPLEXITY                   (default 500, legacy alias)
 *   - GRAPHQL_MAX_COMPLEXITY_AUTHENTICATED     (default 500)
 *   - GRAPHQL_MAX_COMPLEXITY_UNAUTHENTICATED   (default 100, capped at the
 *                                               authenticated budget)
 *
 * Per-client scoping: graphql validation rules receive only a ValidationContext
 * (no request context), so the per-client budget is enforced on the WebSocket
 * surface via assertQueryWithinComplexityBudget() called from onSubscribe,
 * where the authenticated client is known. The static validationRules remain as
 * a backstop that rejects oversized queries before they reach resolvers.
 */

import { GraphQLError, parse } from "graphql";
import depthLimit from "graphql-depth-limit";
import {
  createComplexityRule,
  getComplexity,
  simpleEstimator,
  fieldExtensionsEstimator,
} from "graphql-query-complexity";
import type { DocumentNode } from "graphql";
import type { GraphQLSchema } from "graphql";

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Maximum allowed query depth (nested field selections). Default: 5. */
export const MAX_QUERY_DEPTH = intEnv("GRAPHQL_MAX_DEPTH", 5);

/**
 * Complexity budget for authenticated clients. Default: 500 (matches the
 * previous hardcoded HTTP limit).
 */
export const MAX_QUERY_COMPLEXITY_AUTHENTICATED = intEnv(
  "GRAPHQL_MAX_COMPLEXITY_AUTHENTICATED",
  intEnv("GRAPHQL_MAX_COMPLEXITY", 500),
);

/**
 * Complexity budget for unauthenticated/dev clients. Deliberately lower than
 * the authenticated budget to limit anonymous abuse of the WS surface when
 * GRAPHQL_API_KEY is not set (dev only; production requires the key).
 */
export const MAX_QUERY_COMPLEXITY_UNAUTHENTICATED = Math.min(
  intEnv("GRAPHQL_MAX_COMPLEXITY_UNAUTHENTICATED", 100),
  MAX_QUERY_COMPLEXITY_AUTHENTICATED,
);

/** Returns the complexity budget for a client based on auth state. */
export function getClientComplexityLimit(authenticated: boolean): number {
  return authenticated
    ? MAX_QUERY_COMPLEXITY_AUTHENTICATED
    : MAX_QUERY_COMPLEXITY_UNAUTHENTICATED;
}

const complexityEstimators = [
  fieldExtensionsEstimator(),
  simpleEstimator({ defaultComplexity: 1 }),
];

/**
 * Builds the shared static validation rule set (depth + complexity backstop).
 *
 * Used on both the HTTP (Apollo) and WebSocket (graphql-ws) surfaces so an
 * oversized query is rejected during validation on every transport.
 */
export function createGraphQLValidationRules(
  budget: number = MAX_QUERY_COMPLEXITY_AUTHENTICATED,
) {
  return [
    depthLimit(MAX_QUERY_DEPTH),
    createComplexityRule({
      maximumComplexity: budget,
      estimators: complexityEstimators,
    }),
  ];
}

/**
 * Per-client complexity check (issue #813).
 *
 * Unlike the validation rules, this runs with the request's variables and the
 * client's auth state, so the budget can be scoped per client. Returns GraphQLErrors
 * (empty when the query is within budget). Parse errors are returned untouched so
 * the default validation phase can report them with its own formatting.
 */
export function assertQueryWithinComplexityBudget(params: {
  schema: GraphQLSchema;
  query: string | DocumentNode;
  variables?: Record<string, unknown>;
  operationName?: string | null;
  authenticated: boolean;
}): GraphQLError[] {
  const budget = getClientComplexityLimit(params.authenticated);

  let document: DocumentNode;
  try {
    document =
      typeof params.query === "string" ? parse(params.query) : params.query;
  } catch (err) {
    // Malformed query — let the normal validation phase report it.
    return [];
  }

  const complexity = getComplexity({
    estimators: complexityEstimators,
    schema: params.schema,
    query: document,
    variables: params.variables,
    operationName: params.operationName ?? undefined,
  });

  if (complexity > budget) {
    return [
      new GraphQLError(
        `Query complexity ${complexity} exceeds the limit of ${budget}`,
        { extensions: { code: "QUERY_COMPLEXITY_LIMIT_EXCEEDED" } },
      ),
    ];
  }
  return [];
}
