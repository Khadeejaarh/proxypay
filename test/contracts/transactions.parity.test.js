'use strict';

/**
 * Contract tests: feature parity across v1 and v2 transaction routes (issue #810).
 *
 * These tests assert that the versioned transaction handlers behave equivalently
 * for authorization, idempotency, validation, and status-code semantics. They do
 * NOT change runtime behavior; they only verify it.
 *
 * Intentional differences between v1 and v2 are documented in
 * `INTENTIONAL_DIFFERENCES` below and asserted explicitly so drift is caught.
 */

const request = require('supertest');
const app = require('../../src/app');

// Documented, intentional divergences between the v1 and v2 transaction routes.
// Any new versioned endpoint must add its differences here before shipping.
const INTENTIONAL_DIFFERENCES = {
  // v1 returns the legacy `{ data: ... }` envelope; v2 returns the resource directly.
  responseEnvelope: { v1: 'wrapped', v2: 'bare' },
  // v2 requires an `Idempotency-Key` header; v1 treats it as optional.
  idempotencyKeyRequired: { v1: false, v2: true },
};

const VERSIONS = ['v1', 'v2'];

const basePath = (version) => `/api/${version}/transactions`;

const authHeader = (token = 'test-token') => ({ Authorization: `Bearer ${token}` });

const validTransaction = () => ({
  amount: 1000,
  currency: 'USD',
  reference: 'parity-ref-001',
});

const idempotencyHeaders = (version, key = 'parity-idem-001') =>
  INTENTIONAL_DIFFERENCES.idempotencyKeyRequired[version]
    ? { 'Idempotency-Key': key }
    : {};

describe('transaction route parity (v1 vs v2)', () => {
  describe.each(VERSIONS)('%s authorization parity', (version) => {
    it('rejects unauthenticated requests with 401', async () => {
      const res = await request(app).post(basePath(version)).send(validTransaction());
      expect(res.status).toBe(401);
    });

    it('rejects requests with an invalid token with 401', async () => {
      const res = await request(app)
        .post(basePath(version))
        .set(authHeader('invalid-token'))
        .send(validTransaction());
      expect(res.status).toBe(401);
    });
  });

  describe.each(VERSIONS)('%s validation parity', (version) => {
    it('rejects a missing amount with 400', async () => {
      const res = await request(app)
        .post(basePath(version))
        .set(authHeader())
        .set(idempotencyHeaders(version))
        .send({ currency: 'USD', reference: 'parity-ref-002' });
      expect(res.status).toBe(400);
    });

    it('rejects an unsupported currency with 400', async () => {
      const res = await request(app)
        .post(basePath(version))
        .set(authHeader())
        .set(idempotencyHeaders(version))
        .send({ amount: 1000, currency: 'XXX', reference: 'parity-ref-003' });
      expect(res.status).toBe(400);
    });
  });

  describe.each(VERSIONS)('%s idempotency parity', (version) => {
    it('returns the same result for a repeated idempotency key', async () => {
      const key = `parity-idem-${version}`;
      const payload = validTransaction();

      const first = await request(app)
        .post(basePath(version))
        .set(authHeader())
        .set(idempotencyHeaders(version, key))
        .send(payload);

      const second = await request(app)
        .post(basePath(version))
        .set(authHeader())
        .set(idempotencyHeaders(version, key))
        .send(payload);

      expect(second.status).toBe(first.status);
      expect(second.body).toEqual(first.body);
    });
  });

  describe.each(VERSIONS)('%s status-code parity', (version) => {
    it('returns 201 on successful creation', async () => {
      const res = await request(app)
        .post(basePath(version))
        .set(authHeader())
        .set(idempotencyHeaders(version, `parity-create-${version}`))
        .send(validTransaction());

      expect(res.status).toBe(201);
    });
  });

  describe('intentional differences', () => {
    it('v1 wraps the response in a data envelope while v2 returns it bare', async () => {
      const v1 = await request(app)
        .post(basePath('v1'))
        .set(authHeader())
        .send(validTransaction());
      const v2 = await request(app)
        .post(basePath('v2'))
        .set(authHeader())
        .set(idempotencyHeaders('v2', 'parity-envelope-v2'))
        .send(validTransaction());

      if (INTENTIONAL_DIFFERENCES.responseEnvelope.v1 === 'wrapped') {
        expect(v1.body).toHaveProperty('data');
      }
      if (INTENTIONAL_DIFFERENCES.responseEnvelope.v2 === 'bare') {
        expect(v2.body).not.toHaveProperty('data');
      }
    });

    it('v2 requires an Idempotency-Key header while v1 does not', async () => {
      const v1 = await request(app)
        .post(basePath('v1'))
        .set(authHeader())
        .send(validTransaction());
      expect(v1.status).not.toBe(400);

      const v2 = await request(app)
        .post(basePath('v2'))
        .set(authHeader())
        .send(validTransaction());
      expect(v2.status).toBe(400);
    });
  });
});
