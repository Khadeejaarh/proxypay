# API Versioning

This document describes how versioned transaction routes are mounted, what
behavior is expected to be identical across versions, and which differences are
intentional. It is the reference for the shared contract tests in
`test/contracts/transactions.parity.test.ts`.

## Mounting

Versioned transaction handlers are mounted under their version prefix:

- `v1` → `/api/v1/transactions`
- `v2` → `/api/v2/transactions`

Both versions are served by the same application instance and share the same
authentication middleware, idempotency store, and validation layer. The version
prefix is resolved by the API version middleware before the request reaches the
handler.

## Contract parity

For equivalent operations, `v1` and `v2` MUST behave identically with respect
to the following contract points. The shared contract tests assert each of
these against both versions:

### Authorization

- Requests without credentials return `401`.
- Requests with invalid or expired credentials return `401`.
- Requests with valid credentials but insufficient scope return `403`.
- The same authorization rules apply to both versions; a request that is
  authorized on `v1` is authorized on `v2` and vice versa.

### Idempotency

- A request carrying an `Idempotency-Key` header is deduplicated per key.
- Replaying the same key with the same payload returns the original response
  (same status and body) without creating a second transaction.
- Replaying the same key with a different payload returns `409`.
- Idempotency keys are scoped per version; a key used on `v1` does not collide
  with the same key on `v2`.

### Validation

- Missing required fields return `400` with a validation error body.
- Malformed field types return `400`.
- Unknown fields are rejected consistently across versions.
- Validation error responses use the same error envelope shape in both
  versions.

### Status codes

- Successful creation returns `201`.
- Successful reads return `200`.
- Not-found resources return `404`.
- Conflict conditions (including idempotency conflicts) return `409`.
- Unhandled server errors return `500` with the shared error envelope.

## Intentional differences

Any difference between `v1` and `v2` transaction behavior MUST be listed here
before a new versioned endpoint is added. Currently the following differences
are intentional:

- **Response envelope shape.** `v2` responses wrap the resource in a
  `{ "data": ... }` envelope; `v1` returns the resource at the top level. The
  underlying resource fields are identical.
- **Pagination parameters.** `v2` accepts `cursor`-based pagination; `v1`
  accepts `page`/`limit`. Both return the same item shape.
- **Deprecation headers.** `v1` responses include a `Deprecation` header to
  signal the migration path to `v2`. `v2` responses do not.

All other behavior — authorization, idempotency, validation, and status codes —
is expected to be identical and is covered by the shared contract tests.

## Adding a new versioned endpoint

Before adding a new versioned transaction endpoint:

1. Add the endpoint to both `v1` and `v2` handlers, or document the intentional
   difference in the section above.
2. Extend the shared contract tests to cover the new operation for both
   versions.
3. Confirm authorization, idempotency, validation, and status-code parity in
   the test run.
