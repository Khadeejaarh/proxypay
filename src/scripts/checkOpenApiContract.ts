/**
 * OpenAPI contract check (issue #812).
 *
 * Verifies that the generated OpenAPI document still matches the runtime
 * validation contracts, and (when a committed baseline exists) that no
 * breaking changes have been introduced to required fields or response
 * shapes.
 *
 * Usage: npm run openapi:check
 */

import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { generateOpenAPIDocument } from "../openapi/generator";
import { registerSchema } from "../validation/authSchemas";
import { listTransactionsQuerySchema } from "../validation/transactionQuerySchemas";

const BASELINE_PATH = join(__dirname, "..", "..", "public", "openapi.json");

type Doc = {
  paths?: Record<string, Record<string, any>>;
  components?: { schemas?: Record<string, any> };
};

const errors: string[] = [];
const fail = (message: string) => errors.push(message);

const current = generateOpenAPIDocument() as Doc;

// ---------------------------------------------------------------------------
// 1. Structural contract checks — required fields and response shapes must be
//    present for every documented operation.
// ---------------------------------------------------------------------------

for (const [path, operations] of Object.entries(current.paths ?? {})) {
  for (const [method, operation] of Object.entries(operations)) {
    const opName = `${method.toUpperCase()} ${path}`;
    const responses = operation?.responses ?? {};
    if (Object.keys(responses).length === 0) {
      fail(`${opName}: declares no responses`);
    }
  }
}

// RegisterRequest must be derived from the runtime registerSchema.
const registerSchemaDoc = current.components?.schemas?.RegisterRequest;
if (!registerSchemaDoc) {
  fail("components.schemas.RegisterRequest is missing");
} else {
  const runtimeKeys = Object.keys(registerSchema.shape).sort();
  const documentedKeys = [...(registerSchemaDoc.required ?? [])].sort();
  if (JSON.stringify(runtimeKeys) !== JSON.stringify(documentedKeys)) {
    fail(
      `RegisterRequest required fields ${JSON.stringify(documentedKeys)} do not match runtime schema fields ${JSON.stringify(runtimeKeys)}`,
    );
  }
  const passwordDoc = registerSchemaDoc.properties?.password;
  if (passwordDoc?.minLength !== 12) {
    fail(
      `RegisterRequest.password minLength is ${passwordDoc?.minLength}, runtime requires 12`,
    );
  }
}

// The transactions list query must document the same bounds the runtime
// schema enforces (issue #812: previously max(100) was documented while the
// runtime accepted up to 1000).
const listParams = current.paths?.["/api/v1/transactions"]?.get?.parameters;
if (!Array.isArray(listParams)) {
  fail("GET /api/v1/transactions declares no query parameters");
} else {
  const limitParam: any = listParams.find((p: any) => p.name === "limit");
  const runtimeMax =
    (listTransactionsQuerySchema.shape.limit as any)._def?.checks?.find(
      (c: any) => c.kind === "max",
    )?.value ?? 1000;
  if (limitParam?.schema?.maximum !== runtimeMax) {
    fail(
      `GET /api/v1/transactions limit maximum is ${limitParam?.schema?.maximum}, runtime enforces ${runtimeMax}`,
    );
  }
  if (!limitParam) {
    fail("GET /api/v1/transactions is missing the limit parameter");
  }
}

// ---------------------------------------------------------------------------
// 2. Baseline diff — required fields and response shapes must not disappear.
// ---------------------------------------------------------------------------

if (existsSync(BASELINE_PATH)) {
  const baseline = JSON.parse(
    readFileSync(BASELINE_PATH, "utf8"),
  ) as Doc;

  for (const [path, operations] of Object.entries(baseline.paths ?? {})) {
    const currentPath = current.paths?.[path];
    if (!currentPath) {
      fail(`Breaking change: path ${path} was removed`);
      continue;
    }
    for (const [method, operation] of Object.entries(operations)) {
      const currentOp = currentPath[method];
      if (!currentOp) {
        fail(`Breaking change: ${method.toUpperCase()} ${path} was removed`);
        continue;
      }

      // Required request fields must not be removed or un-required.
      const baselineRequired: string[] =
        operation?.requestBody?.content?.["application/json"]?.schema
          ?.required ?? [];
      const currentSchema =
        currentOp?.requestBody?.content?.["application/json"]?.schema;
      const currentRequired: string[] = currentSchema?.required ?? [];
      for (const field of baselineRequired) {
        if (!currentRequired.includes(field)) {
          fail(
            `Breaking change: ${method.toUpperCase()} ${path} no longer requires "${field}"`,
          );
        }
        if (!(currentSchema?.properties ?? {})[field]) {
          fail(
            `Breaking change: ${method.toUpperCase()} ${path} removed property "${field}"`,
          );
        }
      }

      // Successful response shapes must keep their required fields.
      for (const [status, response] of Object.entries(
        operation?.responses ?? {},
      )) {
        if (!/^[23]/.test(status)) continue;
        const baselineRespRequired: string[] = (
          response as any
        )?.content?.["application/json"]?.schema?.required;
        if (!baselineRespRequired) continue;
        const currentRespRequired: string[] = (
          currentOp?.responses?.[status] as any
        )?.content?.["application/json"]?.schema?.required;
        for (const field of baselineRespRequired) {
          if (!currentRespRequired?.includes(field)) {
            fail(
              `Breaking change: ${method.toUpperCase()} ${path} response ${status} no longer includes required field "${field}"`,
            );
          }
        }
      }
    }
  }
} else {
  console.warn(
    `[openapi:check] No baseline at ${BASELINE_PATH} — running structural checks only. Run "npm run openapi:generate" to create one.`,
  );
}

// ---------------------------------------------------------------------------

if (errors.length > 0) {
  console.error(`OpenAPI contract check failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

console.log("OpenAPI contract check passed.");
