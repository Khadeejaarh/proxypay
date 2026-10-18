/**
 * OpenAPI ↔ runtime contract tests (issue #812).
 *
 * The OpenAPI document is generated from the same Zod schemas the routes
 * validate with. These tests pin the documented required fields and query
 * bounds to the runtime schemas so any drift fails CI.
 */

import { generateOpenAPIDocument } from "../generator";
import { registerSchema } from "../../validation/authSchemas";
import { listTransactionsQuerySchema } from "../../validation/transactionQuerySchemas";

type Doc = {
  paths?: Record<string, Record<string, any>>;
  components?: { schemas?: Record<string, any> };
};

describe("OpenAPI generated from runtime validation contracts", () => {
  let doc: Doc;

  beforeAll(() => {
    doc = generateOpenAPIDocument() as Doc;
  });

  it("generates a document with registered paths", () => {
    expect(Object.keys(doc.paths ?? {}).length).toBeGreaterThan(0);
    expect(doc.paths?.["/api/auth/register"]?.post).toBeDefined();
    expect(doc.paths?.["/api/v1/transactions"]?.get).toBeDefined();
  });

  it("documents RegisterRequest required fields from the runtime registerSchema", () => {
    const schema = doc.components?.schemas?.RegisterRequest;
    expect(schema).toBeDefined();
    expect([...(schema.required ?? [])].sort()).toEqual(
      Object.keys(registerSchema.shape).sort(),
    );
    expect(schema.properties?.password?.minLength).toBe(12);
    expect(schema.properties?.phone_number).toBeDefined();
  });

  it("enforces the same password rules at runtime and in the document", () => {
    // Runtime: a short password is rejected…
    const shortPassword = registerSchema.safeParse({
      phone_number: "+237670000000",
      password: "Short1!aaa",
    });
    expect(shortPassword.success).toBe(false);

    // …and the document advertises the same minimum.
    const schema = doc.components?.schemas?.RegisterRequest;
    expect(schema.properties.password.minLength).toBe(12);
  });

  it("documents the transactions list query from the runtime schema", () => {
    const parameters: any[] = doc.paths?.["/api/v1/transactions"]?.get
      ?.parameters as any[];
    expect(Array.isArray(parameters)).toBe(true);

    const names = parameters.map((p) => p.name);
    expect(names).toEqual(
      expect.arrayContaining(Object.keys(listTransactionsQuerySchema.shape)),
    );

    const limitParam = parameters.find((p) => p.name === "limit");
    expect(limitParam.schema.maximum).toBe(1000);
    expect(limitParam.schema.minimum).toBe(1);
  });

  it("rejects out-of-bounds queries at runtime (limit > 1000)", () => {
    expect(
      listTransactionsQuerySchema.safeParse({ limit: 1001 }).success,
    ).toBe(false);
    expect(listTransactionsQuerySchema.safeParse({ limit: 1000 }).success).toBe(
      true,
    );
  });

  it("declares at least one response for every documented operation", () => {
    for (const [path, operations] of Object.entries(doc.paths ?? {})) {
      for (const [method, operation] of Object.entries(operations)) {
        expect(
          Object.keys((operation as any)?.responses ?? {}).length,
          `${method.toUpperCase()} ${path} must declare responses`,
        ).toBeGreaterThan(0);
      }
    }
  });
});
