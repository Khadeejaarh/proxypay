export interface WebhookEvent<T = any> {
  type: string;
  data: T;
}

export interface PaymentData {
  id: string;
  amount: number;
  status: string;
}

export type StellarNetwork = 'public' | 'testnet' | 'futurenet';

export interface StellarAssetConfig {
  code: string;
  issuer: string;
  network: StellarNetwork;
}

export interface StellarTrustline {
  assetCode: string;
  assetIssuer: string;
  authorized: boolean;
  authorizedToMaintainLiabilities: boolean;
  limit: string;
  balance: string;
}

ex type StellarPayoutValidationErrorCode =
  | 'NETWORK_MISMATCH'
  | 'ASSET_ISSUER_MISMATCH'
  | 'ASSET_CODE_MISMATCH'
  | 'DESTINATION_NOT_FOUND'
  | 'TRUSTLINE_MISSING'
  | 'TRUSTLINE_NOT_AUTHORIZED'
  | 'TRUSTLINE_LIMIT_EXCEEDED';

export interface StellarPayoutValidationError {
  code: StellarPayoutValidationErrorCode;
  message: string;
  retryable: boolean;
}

export interface StellarPayoutValidationResult {
  valid: boolean;
  errors: StellarPayoutValidationError[];
}
