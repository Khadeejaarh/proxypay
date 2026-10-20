import { Counter, Gauge, Registry, collectDefaultMetrics } from 'prom-client';

export const registry = new Registry();
collectDefaultMetrics({ register: registry });

// ---------------------------------------------------------------------------
// Horizon endpoint / failover metrics (issue #791)
//
// Labels MUST be sanitized: only the endpoint host (and optional path) is
// exposed. Credentials, query strings, and auth headers are never included.
// ---------------------------------------------------------------------------

/**
 * Reduce a Horizon URL to a safe, secret-free label value.
 * Strips userinfo, query string, and fragment; keeps host + pathname.
 */
export function sanitizeHorizonEndpoint(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    const path = url.pathname && url.pathname !== '/' ? url.pathname : '';
    return `${url.host}${path}`;
  } catch {
    // Not a parseable URL: fall back to a conservative redaction.
    return 'invalid-endpoint';
  }
}

/** Gauge identifying the currently active Horizon endpoint (1 = active). */
export const horizonActiveEndpoint = new Gauge({
  name: 'horizon_active_endpoint',
  help: 'Currently active Horizon endpoint (1 = active, 0 = inactive).',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

/** Per-node health: 1 = healthy/up, 0 = unhealthy/down. */
export const horizonEndpointUp = new Gauge({
  name: 'horizon_endpoint_up',
  help: 'Health of each configured Horizon endpoint (1 = up, 0 = down).',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

/** Per-node cooldown state: 1 = in cooldown, 0 = available. */
export const horizonEndpointCooldown = new Gauge({
  name: 'horizon_endpoint_cooldown',
  help: 'Whether a Horizon endpoint is in failover cooldown (1 = cooling down, 0 = available).',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

/** Cumulative failure count per endpoint. */
export const horizonEndpointFailures = new Counter({
  name: 'horizon_endpoint_failures_total',
  help: 'Total number of failures observed per Horizon endpoint.',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

/** Cumulative failover/rotation events, to surface repeated failover behavior. */
export const horizonFailoverTotal = new Counter({
  name: 'horizon_failover_total',
  help: 'Total number of Horizon endpoint failover/rotation events.',
  labelNames: ['from_endpoint', 'to_endpoint'] as const,
  registers: [registry],
});

/**
 * Update the active-endpoint gauge so exactly one endpoint reads 1.
 * Callers pass the full list of configured endpoints plus the active one.
 */
export function setActiveHorizonEndpoint(
  endpoints: string[],
  activeEndpoint: string,
): void {
  const active = sanitizeHorizonEndpoint(activeEndpoint);
  for (const endpoint of endpoints) {
    const label = sanitizeHorizonEndpoint(endpoint);
    horizonActiveEndpoint.set({ endpoint: label }, label === active ? 1 : 0);
  }
}

/** Record a failover transition between two endpoints. */
export function recordHorizonFailover(
  fromEndpoint: string,
  toEndpoint: string,
): void {
  horizonFailoverTotal.inc({
    from_endpoint: sanitizeHorizonEndpoint(fromEndpoint),
    to_endpoint: sanitizeHorizonEndpoint(toEndpoint),
  });
}
