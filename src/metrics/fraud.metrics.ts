import { Counter, Gauge, Histogram, Registry } from 'prom-client';

export const fraudMetricsRegistry = new Registry();

// Existing heuristic scoring metrics
export const fraudHeuristicScore = new Histogram({
  name: 'fraud_heuristic_score',
  help: 'Distribution of heuristic fraud scores',
  buckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
  registers: [fraudMetricsRegistry],
});

export const fraudDecisionsTotal = new Counter({
  name: 'fraud_decisions_total',
  help: 'Total fraud decisions by outcome',
  labelNames: ['outcome'],
  registers: [fraudMetricsRegistry],
});

// ML model version tracking so stale deployments are detectable
export const fraudMlModelInfo = new Gauge({
  name: 'fraud_ml_model_info',
  help: 'Active ML fraud model version (value is always 1)',
  labelNames: ['model_version'],
  registers: [fraudMetricsRegistry],
});

// ML score distribution to detect drift
export const fraudMlScore = new Histogram({
  name: 'fraud_ml_score',
  help: 'Distribution of ML fraud model scores',
  labelNames: ['model_version'],
  buckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
  registers: [fraudMetricsRegistry],
});

// Missing / failed ML predictions that force heuristic fallback
export const fraudMlPredictionFailuresTotal = new Counter({
  name: 'fraud_ml_prediction_failures_total',
  help: 'Total ML fraud predictions that were missing or failed',
  labelNames: ['model_version', 'reason'],
  registers: [fraudMetricsRegistry],
});

export const fraudMlFallbackTotal = new Counter({
  name: 'fraud_ml_fallback_total',
  help: 'Total fraud decisions that fell back to heuristics',
  labelNames: ['model_version', 'reason'],
  registers: [fraudMetricsRegistry],
});

// Delayed labels / label latency for model quality evaluation
export const fraudMlLabelLatencySeconds = new Histogram({
  name: 'fraud_ml_label_latency_seconds',
  help: 'Latency between prediction and ground-truth label arrival',
  labelNames: ['model_version'],
  buckets: [60, 300, 900, 3600, 21600, 86400, 604800],
  registers: [fraudMetricsRegistry],
});

export const fraudMlLabelsTotal = new Counter({
  name: 'fraud_ml_labels_total',
  help: 'Total ground-truth labels received for ML fraud model evaluation',
  labelNames: ['model_version', 'label'],
  registers: [fraudMetricsRegistry],
});

// Alert thresholds (documented for Prometheus alerting rules)
export const FRAUD_ML_ALERT_THRESHOLDS = {
  // Fraction of ML predictions failing/missing before alerting
  predictionFailureRatio: 0.05,
  // Fraction of decisions falling back to heuristics before alerting
  fallbackRatio: 0.1,
  // Max acceptable label latency (seconds) before quality signal is stale
  labelLatencySeconds: 86400,
} as const;

export function recordMlModelVersion(modelVersion: string): void {
  fraudMlModelInfo.set({ model_version: modelVersion }, 1);
}

export function recordMlScore(modelVersion: string, score: number): void {
  fraudMlScore.observe({ model_version: modelVersion }, score);
}

export function recordMlPredictionFailure(modelVersion: string, reason: string): void {
  fraudMlPredictionFailuresTotal.inc({ model_version: modelVersion, reason });
}

export function recordMlFallback(modelVersion: string, reason: string): void {
  fraudMlFallbackTotal.inc({ model_version: modelVersion, reason });
}

export function recordMlLabel(modelVersion: string, label: string, latencySeconds: number): void {
  fraudMlLabelsTotal.inc({ model_version: modelVersion, label });
  fraudMlLabelLatencySeconds.observe({ model_version: modelVersion }, latencySeconds);
}
