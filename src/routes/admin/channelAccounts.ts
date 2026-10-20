import { Router, Request, Response } from "express";
import crypto from "crypto";

/**
 * Admin routes for Stellar channel-account provisioning.
 *
 * Issue #792: channel-account signing secrets must never be persisted in
 * plaintext. Secrets are handed to a managed secret store (KMS / secret
 * manager) and only an opaque reference is stored on the channel account.
 * Provisioning requires explicit approval and is bounded by funding limits.
 */

export interface ChannelAccountRecord {
  id: string;
  publicKey: string;
  /** Reference into the managed secret store; never the secret itself. */
  secretRef: string;
  status: "pending_approval" | "approved" | "active" | "revoked";
  fundingLimitStroops: string;
  fundedStroops: string;
  requestedBy: string;
  approvedBy?: string;
  createdAt: string;
  rotatedAt?: string;
}

/**
 * Minimal abstraction over a managed secret store (AWS KMS, GCP Secret
 * Manager, Vault, ...). Implementations must encrypt at rest and return an
 * opaque reference that can later be resolved by the signing service.
 */
export interface SecretStore {
  putSecret(name: string, secret: string): Promise<string>;
  rotateSecret(ref: string, secret: string): Promise<string>;
  deleteSecret(ref: string): Promise<void>;
}

export interface ChannelAccountStore {
  create(record: ChannelAccountRecord): Promise<ChannelAccountRecord>;
  get(id: string): Promise<ChannelAccountRecord | undefined>;
  update(id: string, patch: Partial<ChannelAccountRecord>): Promise<ChannelAccountRecord | undefined>;
  list(): Promise<ChannelAccountRecord[]>;
}

export interface ChannelAccountsDeps {
  secretStore: SecretStore;
  accountStore: ChannelAccountStore;
  /** Default per-account funding ceiling in stroops. */
  defaultFundingLimitStroops?: string;
  /** Hard ceiling that no request may exceed, in stroops. */
  maxFundingLimitStroops?: string;
}

const DEFAULT_FUNDING_LIMIT = "1000000000"; // 100 XLM
const MAX_FUNDING_LIMIT = "10000000000"; // 1000 XLM

function isAdmin(req: Request): boolean {
  const role = (req as any).user?.role;
  return role === "admin" || role === "channel_admin";
}

function parseStroops(value: unknown): bigint | undefined {
  if (typeof value !== "string" && typeof value !== "number") return undefined;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Generate a Stellar ed25519 keypair. The secret is returned to the caller
 * only so it can be pushed into the secret store; it is never persisted here.
 */
function generateKeypair(): { publicKey: string; secret: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const rawPublic = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const rawSecret = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  return {
    publicKey: rawPublic.toString("base64"),
    secret: rawSecret.toString("base64"),
  };
}

export function createChannelAccountsRouter(deps: ChannelAccountsDeps): Router {
  const router = Router();
  const defaultLimit = deps.defaultFundingLimitStroops ?? DEFAULT_FUNDING_LIMIT;
  const maxLimit = deps.maxFundingLimitStroops ?? MAX_FUNDING_LIMIT;

  // Request provisioning of a new channel account. Creates a pending record
  // and stores the signing secret in the managed secret store.
  router.post("/", async (req: Request, res: Response) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "forbidden" });

    const requestedBy = (req as any).user?.id;
    if (!requestedBy) return res.status(401).json({ error: "unauthenticated" });

    const requestedLimit = parseStroops(req.body?.fundingLimitStroops ?? defaultLimit);
    if (requestedLimit === undefined) {
      return res.status(400).json({ error: "invalid fundingLimitStroops" });
    }
    if (requestedLimit > BigInt(maxLimit)) {
      return res.status(400).json({ error: "fundingLimitStroops exceeds maximum" });
    }

    const { publicKey, secret } = generateKeypair();
    const id = crypto.randomUUID();

    let secretRef: string;
    try {
      secretRef = await deps.secretStore.putSecret(`channel-account/${id}`, secret);
    } catch (err) {
      return res.status(502).json({ error: "secret_store_unavailable" });
    }

    const record = await deps.accountStore.create({
      id,
      publicKey,
      secretRef,
      status: "pending_approval",
      fundingLimitStroops: requestedLimit.toString(),
      fundedStroops: "0",
      requestedBy,
      createdAt: new Date().toISOString(),
    });

    // Never echo secretRef or secret material back to the client.
    return res.status(201).json({
      id: record.id,
      publicKey: record.publicKey,
      status: record.status,
      fundingLimitStroops: record.fundingLimitStroops,
    });
  });

  // Approve a pending channel account. Approval must come from a different
  // admin than the requester (separation of duties).
  router.post("/:id/approve", async (req: Request, res: Response) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "forbidden" });
    const approver = (req as any).user?.id;
    if (!approver) return res.status(401).json({ error: "unauthenticated" });

    const record = await deps.accountStore.get(req.params.id);
    if (!record) return res.status(404).json({ error: "not_found" });
    if (record.status !== "pending_approval") {
      return res.status(409).json({ error: "not_pending_approval" });
    }
    if (record.requestedBy === approver) {
      return res.status(403).json({ error: "approver_must_differ_from_requester" });
    }

    const updated = await deps.accountStore.update(record.id, {
      status: "approved",
      approvedBy: approver,
    });
    return res.json({ id: updated?.id, status: updated?.status });
  });

  // Rotate the signing secret for an active channel account.
  router.post("/:id/rotate", async (req: Request, res: Response) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "forbidden" });

    const record = await deps.accountStore.get(req.params.id);
    if (!record) return res.status(404).json({ error: "not_found" });
    if (record.status !== "active" && record.status !== "approved") {
      return res.status(409).json({ error: "not_rotatable" });
    }

    const { secret } = generateKeypair();
    let newRef: string;
    try {
      newRef = await deps.secretStore.rotateSecret(record.secretRef, secret);
    } catch (err) {
      return res.status(502).json({ error: "secret_store_unavailable" });
    }

    const updated = await deps.accountStore.update(record.id, {
      secretRef: newRef,
      rotatedAt: new Date().toISOString(),
    });
    return res.json({ id: updated?.id, rotatedAt: updated?.rotatedAt });
  });

  // Revoke a channel account and purge its secret from the store.
  router.post("/:id/revoke", async (req: Request, res: Response) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "forbidden" });

    const record = await deps.accountStore.get(req.params.id);
    if (!record) return res.status(404).json({ error: "not_found" });

    try {
      await deps.secretStore.deleteSecret(record.secretRef);
    } catch (err) {
      return res.status(502).json({ error: "secret_store_unavailable" });
    }

    const updated = await deps.accountStore.update(record.id, { status: "revoked" });
    return res.json({ id: updated?.id, status: updated?.status });
  });

  // List channel accounts without exposing secret references.
  router.get("/", async (req: Request, res: Response) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "forbidden" });
    const records = await deps.accountStore.list();
    return res.json(
      records.map((r) => ({
        id: r.id,
        publicKey: r.publicKey,
        status: r.status,
        fundingLimitStroops: r.fundingLimitStroops,
        fundedStroops: r.fundedStroops,
        createdAt: r.createdAt,
        rotatedAt: r.rotatedAt,
      })),
    );
  });

  return router;
}
