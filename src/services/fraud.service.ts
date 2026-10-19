import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Counter, Histogram, Gauge, register } from 'prom-client';
import { Transaction } from '../entities/transaction.entity';
import { FraudAlert } from '../entities/fraud-alert.entity';
import { MlPredictionService } from './ml-prediction.service';
import { HeuristicScoringService } from './heuristic-scoring.service';
import { FraudDecision, FraudRiskLevel } from '../types/fraud.types';

const ML_SCORE_HISTOGRAM = new Histogram({
  name: 'fraud_ml_score',
  help: 'Distribution of ML fraud model scores',
  labelNames: ['model_version'],
  buckets: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
});

const ML_PREDICTION_COUNTER = new Counter({
  name: 'fraud_ml_predictions_total',
  help: 'Total ML fraud predictions by outcome',
  labelNames: ['model_version', 'outcome'],
});

const ML_FALLBACK_COUNTER = new Counter({
  name: 'fraud_ml_fallback_total',
  help: 'Total fallbacks to heuristic scoring',
  labelNames: ['model_version', 'reason'],
});

const ML_LABEL_LATENCY = new Histogram({
  name: 'fraud_ml_label_latency_seconds',
  help: 'Latency between prediction and delayed label arrival',
  labelNames: ['model_version'],
  buckets: [60, 300, 900, 3600, 21600, 86400, 604800],
});

const ML_MODEL_INFO = new Gauge({
  name: 'fraud_ml_model_info',
  help: 'Active ML fraud model version (value is always 1)',
  labelNames: ['model_version'],
});

const ML_DRIFT_ALERT = new Counter({
  name: 'fraud_ml_drift_alerts_total',
  help: 'Drift/quality alert threshold breaches',
  labelNames: ['model_version', 'alert'],
});

@Injectable()
export class FraudService {
  private readonly logger = new Logger(FraudService.name);
  private readonly mlScoreDriftThreshold: number;
  private readonly mlMissingRateThreshold: number;
  private readonly mlLabelLatencyThresholdSeconds: number;

  constructor(
    @InjectRepository(Transaction)
    private readonly transactionRepository: Repository<Transaction>,
    @InjectRepository(FraudAlert)
    private readonly fraudAlertRepository: Repository<FraudAlert>,
    private readonly mlPredictionService: MlPredictionService,
    private readonly heuristicScoringService: HeuristicScoringService,
    private readonly configService: ConfigService,
  ) {
    this.mlScoreDriftThreshold = this.configService.get<number>(
      'FRAUD_ML_SCORE_DRIFT_THRESHOLD',
      0.25,
    );
    this.mlMissingRateThreshold = this.configService.get<number>(
      'FRAUD_ML_MISSING_RATE_THRESHOLD',
      0.1,
    );
    this.mlLabelLatencyThresholdSeconds = this.configService.get<number>(
      'FRAUD_ML_LABEL_LATENCY_THRESHOLD_SECONDS',
      86400,
    );
  }

  async evaluateTransaction(transaction: Transaction): Promise<FraudDecision> {
    const heuristicScore = await this.heuristicScoringService.score(transaction);

    let mlScore: number | null = null;
    let modelVersion = 'unknown';
    try {
      const prediction = await this.mlPredictionService.predict(transaction);
      modelVersion = prediction.modelVersion ?? 'unknown';
      mlScore = prediction.score;
      ML_MODEL_INFO.labels(modelVersion).set(1);
      ML_SCORE_HISTOGRAM.labels(modelVersion).observe(mlScore);
      ML_PREDICTION_COUNTER.labels(modelVersion, 'success').inc();
    } catch (error) {
      ML_PREDICTION_COUNTER.labels(modelVersion, 'missing').inc();
      ML_FALLBACK_COUNTER.labels(modelVersion, 'prediction_error').inc();
      this.logger.warn(
        `ML prediction unavailable, falling back to heuristics: ${error.message}`,
      );
    }

    if (mlScore === null) {
      ML_FALLBACK_COUNTER.labels(modelVersion, 'no_score').inc();
    }

    const finalScore = this.blendScores(heuristicScore, mlScore);
    const riskLevel = this.toRiskLevel(finalScore);

    const decision: FraudDecision = {
      transactionId: transaction.id,
      heuristicScore,
      mlScore,
      modelVersion,
      finalScore,
      riskLevel,
      usedFallback: mlScore === null,
    };

    if (riskLevel === FraudRiskLevel.HIGH) {
      await this.fraudAlertRepository.save(
        this.fraudAlertRepository.create({
          transactionId: transaction.id,
          riskLevel,
          score: finalScore,
        }),
      );
    }

    return decision;
  }

  /**
   * Record a delayed label once ground truth is known so model quality and
   * label latency can be evaluated.
   */
  async recordDelayedLabel(
    transactionId: string,
    modelVersion: string,
    predictedAt: Date,
    isFraud: boolean,
  ): Promise<void> {
    const latencySeconds = Math.max(
      0,
      (Date.now() - predictedAt.getTime()) / 1000,
    );
    ML_LABEL_LATENCY.labels(modelVersion).observe(latencySeconds);

    if (latencySeconds > this.mlLabelLatencyThresholdSeconds) {
      ML_DRIFT_ALERT.labels(modelVersion, 'label_latency').inc();
      this.logger.warn(
        `Delayed label for transaction ${transactionId} exceeded threshold ` +
          `(${latencySeconds}s > ${this.mlLabelLatencyThresholdSeconds}s)`,
      );
    }

    await this.transactionRepository.update(transactionId, {
      label: isFraud ? 'fraud' : 'legitimate',
      labeledAt: new Date(),
    });
  }

  /**
   * Evaluate drift/quality signals against alert thresholds. Intended to be
   * called periodically by a monitoring job.
   */
  async checkModelQuality(
    modelVersion: string,
    observedMeanScore: number,
    baselineMeanScore: number,
    missingRate: number,
  ): Promise<void> {
    const drift = Math.abs(observedMeanScore - baselineMeanScore);
    if (drift > this.mlScoreDriftThreshold) {
      ML_DRIFT_ALERT.labels(modelVersion, 'score_drift').inc();
      this.logger.warn(
        `ML score drift detected for model ${modelVersion}: ` +
          `${drift.toFixed(3)} > ${this.mlScoreDriftThreshold}`,
      );
    }

    if (missingRate > this.mlMissingRateThreshold) {
      ML_DRIFT_ALERT.labels(modelVersion, 'missing_predictions').inc();
      this.logger.warn(
        `ML missing prediction rate for model ${modelVersion}: ` +
          `${missingRate.toFixed(3)} > ${this.mlMissingRateThreshold}`,
      );
    }
  }

  private blendScores(heuristicScore: number, mlScore: number | null): number {
    if (mlScore === null) {
      return heuristicScore;
    }
    return heuristicScore * 0.4 + mlScore * 0.6;
  }

  private toRiskLevel(score: number): FraudRiskLevel {
    if (score >= 0.8) {
      return FraudRiskLevel.HIGH;
    }
    if (score >= 0.5) {
      return FraudRiskLevel.MEDIUM;
    }
    return FraudRiskLevel.LOW;
  }
}
