import dotenv from "dotenv";

dotenv.config();

interface StellarConfig {
  network: "testnet" | "public" | "futurenet";
  horizonUrl: string;
  networkPassphrase: string;
  assetCode: string;
  assetIssuer: string;
}

interface Config {
  port: number;
  bridgeApiUrl: string;
  bridgeApiKey: string;
  webhookSecret: string;
  stellar: StellarConfig;
}

const STELLAR_NETWORKS: Record<
  StellarConfig["network"],
  { horizonUrl: string; networkPassphrase: string }
> = {
  testnet: {
    horizonUrl: "https://horizon-testnet.stellar.org",
    networkPassphrase: "Test SDF Network ; September 2015",
  },
  public: {
    horizonUrl: "https://horizon.stellar.org",
    networkPassphrase: "Public Global Stellar Network ; September 2015",
  },
  futurenet: {
    horizonUrl: "https://horizon-futurenet.stellar.org",
    networkPassphrase: "Test SDF Future Network ; October 2022",
  },
};

function resolveStellarNetwork(): StellarConfig["network"] {
  const raw = (process.env.STELLAR_NETWORK || "testnet").toLowerCase();
  if (raw === "testnet" || raw === "public" || raw === "futurenet") {
    return raw;
  }
  throw new Error(
    `Invalid STELLAR_NETWORK "${raw}". Expected one of: testnet, public, futurenet.`
  );
}

function resolveAssetCode(): string {
  const code = (process.env.STELLAR_ASSET_CODE || "").trim();
  if (!code) {
    throw new Error("STELLAR_ASSET_CODE is required for Stellar payouts.");
  }
  if (!/^[A-Za-z0-9]{1,12}$/.test(code)) {
    throw new Error(
      `Invalid STELLAR_ASSET_CODE "${code}". Asset codes must be 1-12 alphanumeric characters.`
    );
  }
  return code;
}

function resolveAssetIssuer(): string {
  const issuer = (process.env.STELLAR_ASSET_ISSUER || "").trim();
  if (!issuer) {
    throw new Error("STELLAR_ASSET_ISSUER is required for Stellar payouts.");
  }
  if (!/^G[A-Z2-7]{55}$/.test(issuer)) {
    throw new Error(
      `Invalid STELLAR_ASSET_ISSUER "${issuer}". Expected a Stellar account ID (G...).`
    );
  }
  return issuer;
}

const stellarNetwork = resolveStellarNetwork();
const stellarNetworkDefaults = STELLAR_NETWORKS[stellarNetwork];

export const config: Config = {
  port: Number(process.env.PORT) || 3000,
  bridgeApiUrl: process.env.BRIDGE_API_URL || "",
  bridgeApiKey: process.env.BRIDGE_API_KEY || "",
  webhookSecret: process.env.WEBHOOK_SECRET || "",
  stellar: {
    network: stellarNetwork,
    horizonUrl: process.env.STELLAR_HORIZON_URL || stellarNetworkDefaults.horizonUrl,
    networkPassphrase:
      process.env.STELLAR_NETWORK_PASSPHRASE || stellarNetworkDefaults.networkPassphrase,
    assetCode: resolveAssetCode(),
    assetIssuer: resolveAssetIssuer(),
  },
};
