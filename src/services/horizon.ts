import { Horizon } from '@stellar/stellar-sdk';
import { Counter, Gauge, Registry } from 'prom-client';
import { logger } from '../utils/logger';
import { config } from '../config';

export interface HorizonEndpoint {
  url: string;
  name: string;
}

export interface EndpointState {
  endpoint: HorizonEndpoint;
  healthy: boolean;
  cooldownUntil: number;
  consecutiveFailures: number;
  totalFailures: number;
  lastCheckedAt: number;
}

const COOLDOWN_MS = 30_000;
const MAX_CONSECUTIVE_FAILURES = 3;

/**
 * Strip credentials/query params from a Horizon URL so metric labels never
 * leak API keys, tokens, or auth headers.
 */
export function sanitizeEndpoint(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return 'invalid-endpoint';
  }
}

const registry = new Registry();

const activeEndpointGauge = new Gauge({
  name: 'horizon_active_endpoint',
  help: 'Currently active Horizon endpoint (1 = active)',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

const endpointHealthyGauge = new Gauge({
  name: 'horizon_endpoint_healthy',
  help: 'Health of each configured Horizon endpoint (1 = up, 0 = down)',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

const endpointCooldownGauge = new Gauge({
  name: 'horizon_endpoint_in_cooldown',
  help: 'Whether a Horizon endpoint is in cooldown (1 = cooling down)',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

const endpointConsecutiveFailuresGauge = new Gauge({
  name: 'horizon_endpoint_consecutive_failures',
  help: 'Consecutive failures for a Horizon endpoint',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

const endpointTotalFailuresCounter = new Counter({
  name: 'horizon_endpoint_failures_total',
  help: 'Total failures observed per Horizon endpoint',
  labelNames: ['endpoint'] as const,
  registers: [registry],
});

const failoverCounter = new Counter({
  name: 'horizon_failovers_total',
  help: 'Total number of Horizon endpoint failovers',
  registers: [registry],
});

const healthyEndpointGauge = new Gauge({
  name: 'horizon_healthy_endpoints',
  help: 'Number of currently healthy Horizon endpoints',
  registers: [registry],
});

export function getHorizonMetricsRegistry(): Registry {
  return registry;
}

export class HorizonFailoverClient {
  private readonly states: EndpointState[];
  private activeIndex = 0;

  constructor(endpoints: HorizonEndpoint[]) {
    if (endpoints.length === 0) {
      throw new Error('At least one Horizon endpoint must be configured');
    }
    this.states = endpoints.map((endpoint) => ({
      endpoint,
      healthy: true,
      cooldownUntil: 0,
      consecutiveFailures: 0,
      totalFailures: 0,
      lastCheckedAt: 0,
    }));
    this.publishMetrics();
  }

  getActiveEndpoint(): HorizonEndpoint {
    return this.states[this.activeIndex].endpoint;
  }

  getActiveServer(): Horizon.Server {
    return new Horizon.Server(this.getActiveEndpoint().url);
  }

  getEndpointStates(): ReadonlyArray<EndpointState> {
    return this.states;
  }

  private isInCooldown(state: EndpointState, now: number): boolean {
    return state.cooldownUntil > now;
  }

  private markFailure(state: EndpointState): void {
    state.consecutiveFailures += 1;
    state.totalFailures += 1;
    state.healthy = false;
    state.lastCheckedAt = Date.now();
    if (state.consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
      state.cooldownUntil = Date.now() + COOLDOWN_MS;
    }
    endpointTotalFailuresCounter.inc({ endpoint: sanitizeEndpoint(state.endpoint.url) });
  }

  private markSuccess(state: EndpointState): void {
    state.consecutiveFailures = 0;
    state.healthy = true;
    state.cooldownUntil = 0;
    state.lastCheckedAt = Date.now();
  }

  private rotate(): void {
    const now = Date.now();
    const count = this.states.length;
    for (let offset = 1; offset <= count; offset += 1) {
      const candidate = (this.activeIndex + offset) % count;
      const state = this.states[candidate];
      if (!this.isInCooldown(state, now)) {
        if (candidate !== this.activeIndex) {
          failoverCounter.inc();
          logger.warn(
            { from: sanitizeEndpoint(this.states[this.activeIndex].endpoint.url), to: sanitizeEndpoint(state.endpoint.url) },
            'Horizon endpoint failover',
          );
        }
        this.activeIndex = candidate;
        return;
      }
    }
    logger.error('All Horizon endpoints are in cooldown; retaining current endpoint');
  }

  /**
   * Execute an operation against the active Horizon endpoint, failing over to
   * the next healthy endpoint on error.
   */
  async execute<T>(operation: (server: Horizon.Server) => Promise<T>): Promise<T> {
    const attempts = this.states.length;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const state = this.states[this.activeIndex];
      try {
        const result = await operation(new Horizon.Server(state.endpoint.url));
        this.markSuccess(state);
        this.publishMetrics();
        return result;
      } catch (error) {
        lastError = error;
        this.markFailure(state);
        this.publishMetrics();
        this.rotate();
        this.publishMetrics();
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Horizon request failed on all endpoints');
  }

  /**
   * Publish current failover state to Prometheus. Labels are sanitized so no
   * secrets are exposed.
   */
  publishMetrics(): void {
    const now = Date.now();
    const activeLabel = sanitizeEndpoint(this.getActiveEndpoint().url);
    let healthyCount = 0;

    for (const state of this.states) {
      const label = sanitizeEndpoint(state.endpoint.url);
      const inCooldown = this.isInCooldown(state, now);
      if (state.healthy && !inCooldown) {
        healthyCount += 1;
      }
      endpointHealthyGauge.set({ endpoint: label }, state.healthy ? 1 : 0);
      endpointCooldownGauge.set({ endpoint: label }, inCooldown ? 1 : 0);
      endpointConsecutiveFailuresGauge.set({ endpoint: label }, state.consecutiveFailures);
      activeEndpointGauge.set({ endpoint: label }, label === activeLabel ? 1 : 0);
    }

    healthyEndpointGauge.set(healthyCount);
  }
}

let defaultClient: HorizonFailoverClient | null = null;

export function getHorizonClient(): HorizonFailoverClient {
  if (!defaultClient) {
    const endpoints = config.horizonEndpoints ?? [{ url: config.horizonUrl, name: 'primary' }];
    defaultClient = new HorizonFailoverClient(endpoints);
  }
  return defaultClient;
}
