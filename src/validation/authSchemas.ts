/**
 * Runtime request-validation schemas shared by Express handlers and the
 * OpenAPI generator (issue #812).
 *
 * This is the single source of truth for auth request constraints: routes
 * use it via `validateRequest` / `safeParse`, and `src/openapi` registers
 * the exact same object so documented constraints cannot drift from what
 * the endpoints actually accept.
 */

import { z } from "zod";

/** POST /api/auth/register — also re-exported from src/routes/auth.ts. */
export const registerSchema = z.object({
  phone_number: z.string().min(1, "phone_number is required"),
  password: z
    .string()
    .min(12, "Password must be at least 12 characters")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(
      /[^A-Za-z0-9]/,
      "Password must contain at least one special character",
    ),
});

export type RegisterRequest = z.infer<typeof registerSchema>;
