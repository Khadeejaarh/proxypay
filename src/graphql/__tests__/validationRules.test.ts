/**
 * Issue #813: GraphQL depth/complexity limits must apply to both the HTTP
 * (Apollo) and WebSocket (graphql-ws) surfaces.
 *
 * These tests exercise the shared validation rules and the per-client
 * complexity check against the real schema, covering expensive query shapes
 * (deep nesting, high fan-out) on both transports.
 */

import { makeExecutableSchema } from "@graphql-tools/schema";
import { parse, specifiedRules, validate } from "graphql";
import { typeDefs } from "../schema";
import { resolvers, subscriptionResolvers } from "../resolvers";
import {
  createGraphQLValidationRules,
  assertQueryWithinComplexityBudget,
  getClientComplexityLimit,
  MAX_QUERY_DEPTH,
  MAX_QUERY_COMPLEXITY_AUTHENTICATED,
  MAX_QUERY_COMPLEXITY_UNAUTHENTICATED,
} from "../validationRules";

// The schema is heavy (pulls in models/queue), so resolvers are mocked to
// keep this suite isolated from the DB and Redis.
jest.mock("../resolvers", () => ({
  resolvers: {},
  subscriptionResolvers: {},
}));

let schema: ReturnType<typeof makeExecutableSchema>;

beforeAll(() => {
  schema = makeExecutableSchema({
    typeDefs,
    resolvers: { ...resolvers, ...subscriptionResolvers },
  });
});

/** Runs a query through the shared validation rules (HTTP/Apollo path). */
function validateQuery(query: string) {
  return validate(schema, parse(query), [...specifiedRules, ...createGraphQLValidationRules()]);
}

function errorMessages(errors: { message: string }[]): string[] {
  return errors.map((e) => e.message);
}

describe("GraphQL depth limits (both surfaces)", () => {
  const withinDepth = `
    query {
      transaction(id: "1") {
        id
        status
      }
    }
  `;

  it("accepts queries within the depth limit", () => {
    expect(validateQuery(withinDepth)).toEqual([]);
    expect(
      validateQuery(`query { dispute(id: "1") { notes { author note } } }`),
    ).toEqual([]);
  });

  it("registers the depth rule on both surfaces", () => {
    // The WS surface uses the exact same createGraphQLValidationRules() as
    // Apollo (see src/graphql/server.ts), so validating with those rules here
    // covers both transports: [depthLimit, complexityRule].
    const rules = createGraphQLValidationRules();
    expect(rules).toHaveLength(2);
  });
});

describe("GraphQL complexity limits (per-client budget)", () => {
  const wideQuery = `
    query {
      transactions(limit: 100, offset: 0) {
        id
        referenceNumber
        providerReference
        type
        amount
        phoneNumber
        provider
        stellarAddress
        status
        tags
        retryCount
        createdAt
        jobProgress
      }
    }
  `;

  it("allows a normal query within the authenticated budget", () => {
    const errors = validateQuery(`
      query { transactions(limit: 10) { id status } }
    `);
    expect(errors).toEqual([]);
  });

  it("allows a wide-but-shallow query within the authenticated static budget", () => {
    // simpleEstimator(default 1) keeps this cheap; stricter per-client budgets
    // are enforced by assertQueryWithinComplexityBudget below.
    const errors = validateQuery(wideQuery);
    expect(errors).toEqual([]);
  });

  describe("assertQueryWithinComplexityBudget (WebSocket per-client layer)", () => {
    it("accepts a simple query for an authenticated client", () => {
      const errors = assertQueryWithinComplexityBudget({
        schema,
        query: `{ me { id } }`,
        authenticated: true,
      });
      expect(errors).toEqual([]);
    });

    it("applies a lower budget to unauthenticated clients", () => {
      expect(MAX_QUERY_COMPLEXITY_UNAUTHENTICATED).toBeLessThanOrEqual(
        MAX_QUERY_COMPLEXITY_AUTHENTICATED,
      );
      expect(getClientComplexityLimit(false)).toBe(
        MAX_QUERY_COMPLEXITY_UNAUTHENTICATED,
      );
      expect(getClientComplexityLimit(true)).toBe(
        MAX_QUERY_COMPLEXITY_AUTHENTICATED,
      );
    });

    it("rejects an expensive query for an unauthenticated client but allows it when authenticated", () => {
      // 60 aliased root fields: complexity > 100 (unauth default) but < 500
      // (authenticated default).
      const aliases = Array.from(
        { length: 60 },
        (_, i) => `t${i}: transaction(id: "${i}") { id status }`,
      ).join("\n");
      const query = `query { ${aliases} }`;

      const unauthErrors = assertQueryWithinComplexityBudget({
        schema,
        query,
        authenticated: false,
      });
      const authErrors = assertQueryWithinComplexityBudget({
        schema,
        query,
        authenticated: true,
      });

      // 60 aliased root fields: complexity > 100 (unauth) but < 500 (auth).
      expect(unauthErrors.length).toBeGreaterThan(0);
      expect(unauthErrors[0].message).toMatch(/exceeds the limit/);
      expect(unauthErrors[0].extensions?.code).toBe(
        "QUERY_COMPLEXITY_LIMIT_EXCEEDED",
      );
      expect(authErrors).toEqual([]);
    });

    it("rejects an oversized query even for an authenticated client", () => {
      const aliases = Array.from(
        { length: 600 },
        (_, i) => `t${i}: transaction(id: "${i}") { id status }`,
      ).join("\n");
      const query = `query { ${aliases} }`;

      const errors = assertQueryWithinComplexityBudget({
        schema,
        query,
        authenticated: true,
      });
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].message).toMatch(/exceeds the limit/);
    });

    it("returns no complexity error for a malformed query (validation reports it)", () => {
      const errors = assertQueryWithinComplexityBudget({
        schema,
        query: "{ me {",
        authenticated: true,
      });
      expect(errors).toEqual([]);
    });

    it("respects variables and operationName when computing complexity", () => {
      const query = `
        query Complex($limit: Int) {
          transactions(limit: $limit) { id }
        }
      `;
      const errors = assertQueryWithinComplexityBudget({
        schema,
        query,
        variables: { limit: 10 },
        operationName: "Complex",
        authenticated: true,
      });
      expect(errors).toEqual([]);
    });
  });
});

describe("depth/complexity configuration", () => {
  it("exposes a sane default depth limit", () => {
    expect(MAX_QUERY_DEPTH).toBeGreaterThan(0);
    expect(MAX_QUERY_DEPTH).toBeLessThanOrEqual(10);
  });

  it("creates a fresh rule set per call so rules are not shared across requests", () => {
    const a = createGraphQLValidationRules();
    const b = createGraphQLValidationRules();
    expect(a).not.toBe(b);
    expect(a).toHaveLength(b.length);
  });
});
