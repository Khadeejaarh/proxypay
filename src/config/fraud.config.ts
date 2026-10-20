/**
 * Fraud service configuration.
 *
 * Blends an ML verdict with heuristic scoring. The monitoring block below
 * exposes the operational quality signals required to detect model drift and
 * degraded fallback behavior (issue #772).
 */
export interface FraudMonitoringConfig {
  /** Prometheus metric name prefix for fraud ML quality metrics. */
  metricsPrefix: string;
  /** Label key used to expose the deployed ML model version. */
  modelVersionLabel: string;
  /** Histogram buckets for the ML score distribution (0..1). */
  scoreBuckets: number[];
  /** Alert when the fraction of missing/failed ML predictions exceeds this. */
  missingPredictionRateThreshold: number;
  /** Alert when the ML score distribution drifts beyond this (PSI). */
  scoreDriftPsiThreshold: number;
  /** Alert when delayed labels are older than this (seconds). */
  labelLatencySecondsThreshold: number;
  /** Minimum labeled sample size before drift/quality alerts fire. */
  minLabeledSamples: number;
  /** Fallback to heuristics when the ML model is stale or degraded. */
  fallback: {
    enabled: boolean;
    /** Fall back when the deployed model version differs from the expected one. */
    onStaleModelVersion: boolean;
    /** Fall back when missing-prediction rate exceeds the threshold. */
    onMissingPredictions: boolean;
    /** Fall back when score drift exceeds the threshold. */
    onScoreDrift: boolean;
  };
}

export interface FraudConfig {
  mlEnabled: boolean;
  /** Weight applied to the ML verdict when blending with heuristics. */
  mlWeight: number;
  /** Expected ML model version; mismatch signals a stale deployment. */
  expectedModelVersion: string;
  monitoring: FraudMonitoringConfig;
}

export const fraudConfig: FraudConfig = {
  mlEnabled: true,
  mlWeight: 0.6,
  expectedModelVersion: 'fraud-ml-v1',
  monitoring: {
    metricsPrefix: 'fraud_ml',
    modelVersionLabel: 'model_version',
    scoreBuckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
    missingPredictionRateThreshold: 0.05,
    scoreDriftPsiThreshold: 0.2,
    labelLatencySecondsThreshold: 86400,
    minLabeledSamples: 200,
    fallback: {
      enabled: true,
      onStaleModelVersion: true,
      onMissingPredictions: true,
      onScoreDrift: true,
    },
  },
};
