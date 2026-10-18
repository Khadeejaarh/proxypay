/**
 * Generate the OpenAPI document from the runtime validation contracts and
 * write it to public/openapi.json.
 *
 * The spec is generated from the same Zod schemas the routes validate with
 * (see src/validation/* and src/openapi/*), so it cannot drift from runtime
 * behaviour. The committed baseline also serves as the fallback consumed by
 * sdk-publish.yml when the live server is unavailable.
 */

import { writeFileSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import { generateOpenAPIDocument } from "../openapi/generator";

const outputPath = join(__dirname, "..", "..", "public", "openapi.json");

mkdirSync(dirname(outputPath), { recursive: true });

const document = generateOpenAPIDocument();
writeFileSync(outputPath, `${JSON.stringify(document, null, 2)}\n`, "utf8");

const pathCount = Object.keys((document as any).paths ?? {}).length;
console.log(`OpenAPI document written to ${outputPath} (${pathCount} paths)`);
