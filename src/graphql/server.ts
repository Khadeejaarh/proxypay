import type { Application, Request } from "express";
import { ApolloServer } from "apollo-server-express";
import {
  ApolloServerPluginLandingPageGraphQLPlayground,
  ApolloServerPluginLandingPageProductionDefault,
} from "apollo-server-core";
// @ts-expect-error ESM module
import { makeExecutableSchema } from "@graphql-tools/schema";
import { WebSocketServer } from "ws";
import { useServer, type ServerCleanup } from "graphql-ws/use/ws";
import { typeDefs } from "./schema";
import { resolvers, subscriptionResolvers } from "./resolvers";
import { buildGraphqlContext } from "./context";
import { Server } from "http";
import { createAPQCache } from "./apqCache";
import { createGraphQLValidationRules, assertQueryWithinComplexityBudget } from "./validationRules";
import { verifyTokenStateful } from "../middleware/auth";
import { isAccountActive } from "../middleware/checkAccountStatus";
import {
  wsSessionRegistry,
  tokenExpiryFromClaims,
  sessionIdFromClaims,
  WS_AUTH_POLICY_VIOLATION,
  WS_REVOKED_MESSAGE,
} from "../websocket/wsSessionAuth";
import { GraphQLError } from "graphql";

// Merge resolvers with subscription resolvers
const mergedResolvers = {
  ...resolvers,
  ...subscriptionResolvers,
};

export async function startApolloServer(
  app: Application,
  httpServer: Server,
): Promise<ServerCleanup | null> {
  const schema = makeExecutableSchema({
    typeDefs,
    resolvers: mergedResolvers,
  });

  // APQ cache — Redis-backed, degrades gracefully on Redis downtime
  const apqCache = createAPQCache();

  const server = new ApolloServer({
    schema,
    context: ({ req }: { req: Request }) => buildGraphqlContext(req),

    // ---------------------------------------------------------------------------
    // Automatic Persisted Queries (APQ)
    // Clients send a SHA-256 hash of the query instead of the full string.
    // On cache miss Apollo returns PersistedQueryNotFound; the client retries
    // with the full query + hash, which is then stored in Redis for future hits.
    // ---------------------------------------------------------------------------
    persistedQueries: {
      cache: apqCache,
      // ttl is managed by the cache adapter itself (APQ_TTL_SECONDS env var)
    },

  // Shared depth/complexity rules (issue #813). The rule factory is called
  // per validation run so the complexity budget can be scoped to the
  // authenticated client (see getClientComplexityLimit).
  validationRules: createGraphQLValidationRules(),

    plugins: [
      process.env.NODE_ENV === "production"
        ? ApolloServerPluginLandingPageProductionDefault({ footer: false })
        : ApolloServerPluginLandingPageGraphQLPlayground(),
      // Plugin for proper shutdown of WebSocket server
      {
        async serverWillStart() {
          return {
            async drainServer() {
              await serverCleanup.dispose();
            },
          };
        },
      },
    ],
  });

  await server.start();
  // apollo-server-express bundles its own @types/express; cast avoids duplicate-type errors.
  server.applyMiddleware({ app: app as never, path: "/graphql", cors: false });

  // Create the WebSocket server for subscriptions
  const wsServer = new WebSocketServer({
    server: httpServer,
    path: "/graphql",
  });

  // Set up the graphql-ws server
  const serverCleanup = useServer(
    {
      schema,
      // Issue #813: the WebSocket surface previously had no depth/complexity
      // limits — only HTTP did. The static rules act as a backstop; the
      // per-client budget is enforced in onSubscribe where auth is known.
      validationRules: createGraphQLValidationRules(),
      context: (ctx: any) => {
        const req = ctx.extra.request as Request | undefined;
        const jwtClaims = ctx.extra.jwtClaims;
        // Build base context from HTTP request, then overlay WS auth
        const base = buildGraphqlContext(req as Request);
        if (jwtClaims) {
          base.auth = { authenticated: true, subject: jwtClaims.userId };
        }
        return base;
      },
      onSubscribe: (ctx: any, msg: any) => {
        // ── Revalidate auth on every operation (issue #814) ─────────────
        // A subscription can outlive the token that opened it, so revoked or
        // expired credentials must be rejected here, not only at handshake.
        const claims = ctx.extra?.jwtClaims as
          | { userId?: string; exp?: number }
          | undefined;
        if (claims?.userId) {
          if (wsSessionRegistry.isRevoked(claims.userId)) {
            return [
              new GraphQLError(WS_REVOKED_MESSAGE, {
                extensions: { code: "UNAUTHENTICATED" },
              }),
            ];
          }
          const exp = tokenExpiryFromClaims(claims);
          if (exp !== null && exp <= Math.floor(Date.now() / 1000)) {
            return [
              new GraphQLError("Token expired", {
                extensions: { code: "UNAUTHENTICATED" },
              }),
            ];
          }
        }

        // ── Per-client complexity budget (issue #813) ──────────────────
        // validationRules only see a ValidationContext, so the per-client
        // budget is enforced here, where the connection's auth state is known.
        const authenticated = !!ctx.extra?.jwtClaims;
        const errors = assertQueryWithinComplexityBudget({
          schema,
          query: msg.payload?.query ?? "",
          variables: msg.payload?.variables,
          operationName: msg.payload?.operationName,
          authenticated,
        });
        if (errors.length > 0) {
          return errors;
        }
        return undefined;
      },
      onConnect: async (ctx: any) => {
        // ── JWT authentication on WS handshake ──────────────────────────
        // Clients must pass: connectionParams: { authToken: "<jwt>" }
        const token =
          ctx.connectionParams?.authToken ||
          ctx.connectionParams?.Authorization?.replace(/^Bearer\s+/i, "");

        // Allow unauthenticated in dev when no GRAPHQL_API_KEY is set
        const apiKeyRequired = !!process.env.GRAPHQL_API_KEY;

        if (!token) {
          if (apiKeyRequired) {
            console.warn("[WS] Rejected unauthenticated connection — no authToken");
            return false; // graphql-ws closes the connection
          }
          wsSessionRegistry.ensureReaper();
          return true;
        }

        try {
          // Stateful verification: cryptographic check PLUS Redis-backed
          // revocation / session-binding validation (issue #814).
          const claims = await verifyTokenStateful(String(token));
          const userId = claims.userId;
          if (!userId) throw new Error("Token is missing a userId claim");

          // A password change / logout may have flushed sessions after this
          // token was issued; refuse to open a socket in that case.
          if (wsSessionRegistry.isRevoked(userId)) {
            console.warn(`[WS] Rejected revoked session for user ${userId}`);
            return false;
          }

          // Reject frozen/suspended/deactivated accounts (issue #814). Fail
          // closed: a user we cannot verify as active is not allowed in.
          if (!(await isAccountActive(userId))) {
            console.warn(`[WS] Rejected connection for inactive user ${userId}`);
            return false;
          }

          // Attach claims to context so subscription resolvers can access them
          ctx.extra.jwtClaims = claims;

          // Track the session so it can be terminated on revocation/expiry.
          const socket = ctx.extra?.socket as
            | { close?: (code?: number, reason?: string) => void }
            | undefined;
          const session = {
            userId,
            tokenExpiresAt: tokenExpiryFromClaims(claims),
            sessionId: sessionIdFromClaims(claims),
            close: (code = WS_AUTH_POLICY_VIOLATION, reason = WS_REVOKED_MESSAGE) =>
              socket?.close?.(code, reason),
          };
          ctx.extra.wsSession = session;
          wsSessionRegistry.add(session);
          wsSessionRegistry.ensureReaper();

          console.log(`[WS] Authenticated connection for user ${userId}`);
        } catch (err) {
          console.warn("[WS] Rejected connection — invalid token:", (err as Error).message);
          return false;
        }

        return true;
      },
      onDisconnect: (ctx: any) => {
        const session = ctx.extra?.wsSession;
        if (session) {
          wsSessionRegistry.remove(session);
          ctx.extra.wsSession = undefined;
        }
        console.log("WebSocket subscription disconnected");
      },
      onError: (_ctx: any, err: any) => {
        console.error("WebSocket subscription error:", err);
      },
    },
    wsServer,
  );

  return serverCleanup;
}
