import dotenv from "dotenv";

dotenv.config();

interface Config {
  port: number;
  bridgeApiUrl: string;
  bridgeApiKey: string;
  webhookSecret: string;
  homeDomain: string;
  serverSigningKey: string;
  challengeTtlSeconds: number;
  redisUrl: string;
}

export const config: Config = {
  port: Number(process.env.PORT) || 3000,
  bridgeApiUrl: process.env.BRIDGE_API_URL || "",
  bridgeApiKey: process.env.BRIDGE_API_KEY || "",
  webhookSecret: process.env.WEBHOOK_SECRET || "",
  homeDomain: process.env.HOME_DOMAIN || "",
  serverSigningKey: process.env.SERVER_SIGNING_KEY || "",
  challengeTtlSeconds: Number(process.env.CHALLENGE_TTL_SECONDS) || 300,
  redisUrl: process.env.REDIS_URL || "",
};
