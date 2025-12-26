import assert from "node:assert";
import { afterEach, describe, it } from "node:test";
import express from "express";
import request from "supertest";
import admin from "firebase-admin";
import { DecodedIdToken } from "firebase-admin/auth";
import { firebaseAuthMiddleware } from "../src/middleware/firebaseAuthMiddleware";
import { requireAuth } from "../src/guards/requireAuth";
import { requireRole } from "../src/guards/requireRole";
import { AuthenticatedRequest } from "../src/types/AuthenticatedRequest";
import { Role } from "../src/types/Roles";

type TokenPayload = DecodedIdToken & { roles?: Role[]; tenant?: string };

const makeToken = (
  overrides: Partial<DecodedIdToken> & { uid?: string; roles?: Role[]; tenant?: string } = {}
): TokenPayload =>
  ({
    aud: "aud",
    auth_time: Date.now(),
    exp: Date.now() + 60_000,
    firebase: {} as any,
    iat: Date.now(),
    iss: "issuer",
    sub: overrides.uid ?? "subject",
    uid: overrides.uid ?? "subject",
    ...overrides,
  } as TokenPayload);

const createInMemoryAuthClient = (tokens: Record<string, TokenPayload>) => ({
  verifyIdToken: async (token: string) => {
    const payload = tokens[token];
    if (!payload) {
      throw new Error("invalid token");
    }
    return payload;
  },
});

const buildApp = ({
  authClient,
  useRoleHandler = true,
}: {
  authClient?: ReturnType<typeof createInMemoryAuthClient>;
  useRoleHandler?: boolean;
}) => {
  const app = express();
  app.use(express.json());
  app.use(firebaseAuthMiddleware({ authClient }));

  app.get(
    "/protected",
    requireAuth((req, res) => {
      res.json({ uid: req.auth!.uid });
    })
  );

  if (useRoleHandler) {
    app.get(
      "/admin",
      requireRole("admin", (req, res) => {
        res.json({ uid: req.auth!.uid });
      })
    );

    app.get(
      "/support-or-admin",
      requireRole(["admin", "support"], (req, res) => {
        res.json({ uid: req.auth!.uid });
      })
    );
  }

  app.get("/identity", (req, res) => {
    const auth = (req as AuthenticatedRequest).auth!;
    res.json({ uid: auth.uid, roles: auth.token.roles, tenant: auth.token.tenant });
  });

  return app;
};

const tokens = {
  "token-user": makeToken({ uid: "user-123", roles: ["user"] }),
  "token-identity": makeToken({ uid: "user-456" }),
  "token-admin": makeToken({ uid: "admin-001", roles: ["admin"] }),
  "token-support": makeToken({ uid: "support-007", roles: ["support"] }),
  "token-no-roles": makeToken({ uid: "user-999" }),
  "token-tenant": makeToken({ uid: "user-789", roles: ["admin"], tenant: "tenant-42" }),
};

const originalAdminAuth = admin.auth;

afterEach(() => {
  Object.defineProperty(admin, "auth", { value: originalAdminAuth, configurable: true });
});

describe("integration: authenticate incoming requests", () => {
  // Feature: Authenticate incoming requests | Scenario: Request with a valid identity token is accepted
  it("accepts a request with a valid identity token", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/protected")
      .set("Authorization", "Bearer token-user")
      .expect(200, { uid: "user-123" });
  });

  // Feature: Authenticate incoming requests | Scenario: Request without an identity token is rejected
  it("rejects requests without an identity token", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app).get("/protected").expect(401, { error: "Unauthorized" });
  });

  // Feature: Authenticate incoming requests | Extra: invalid token
  it("rejects requests with invalid tokens", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/protected")
      .set("Authorization", "Bearer token-invalid")
      .expect(401, { error: "Invalid token" });
  });
});

describe("integration: protect handlers that require authentication", () => {
  // Feature: Protect handlers that require authentication | Scenario: Protected operation is executed by an authenticated user
  it("executes protected handler for authenticated user", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/protected")
      .set("Authorization", "Bearer token-user")
      .expect(200, { uid: "user-123" });
  });

  // Feature: Protect handlers that require authentication | Scenario: Protected operation is blocked for unauthenticated requests
  it("blocks unauthenticated access to protected handler", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app).get("/protected").expect(401, { error: "Unauthorized" });
  });
});

describe("integration: authorize access based on user roles", () => {
  // Feature: Authorize access based on user roles | Scenario: User with required role can access the operation
  it("allows user with required role", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/admin")
      .set("Authorization", "Bearer token-admin")
      .expect(200, { uid: "admin-001" });
  });

  // Feature: Authorize access based on user roles | Scenario: User without required role cannot access the operation
  it("blocks user without required role", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/admin")
      .set("Authorization", "Bearer token-user")
      .expect(403, { error: "Forbidden" });
  });

  // Feature: Authorize access based on user roles | Scenario Outline: User with any allowed role can access the operation | Example: support-007
  it("allows any role from an allowed list", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/support-or-admin")
      .set("Authorization", "Bearer token-support")
      .expect(200, { uid: "support-007" });
  });
});

describe("integration: reject access when role information is missing", () => {
  // Feature: Reject access when role information is missing | Scenario: User without role information cannot access a role-protected operation
  it("blocks role-protected operations when roles are absent", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/admin")
      .set("Authorization", "Bearer token-no-roles")
      .expect(403, { error: "Forbidden" });
  });
});

describe("integration: compose authentication and authorization", () => {
  // Feature: Compose authentication and authorization rules | Scenario: Authentication is checked before role authorization
  it("rejects unauthenticated requests before role checks", async () => {
    let roleChecked = false;
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens), useRoleHandler: false });

    app.get(
      "/role-first",
      requireRole("admin", (_req, res) => {
        roleChecked = true;
        res.json({ ok: true });
      })
    );

    const response = await request(app).get("/role-first");
    assert.strictEqual(response.status, 401);
    assert.strictEqual(response.body.error, "Unauthorized");
    assert.strictEqual(roleChecked, false);
  });

  // Feature: Compose authentication and authorization rules | Extra: role authorization after authentication
  it("authorizes only after successful authentication", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens), useRoleHandler: false });

    app.get(
      "/role-first",
      requireRole("admin", (_req, res) => {
        res.json({ ok: true });
      })
    );

    await request(app)
      .get("/role-first")
      .set("Authorization", "Bearer token-no-roles")
      .expect(403, { error: "Forbidden" });
  });
});

describe("integration: expose authenticated user identity", () => {
  // Feature: Expose the authenticated user identity | Scenario: Access the authenticated user identifier
  it("exposes uid on the request", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/identity")
      .set("Authorization", "Bearer token-identity")
      .expect(200, { uid: "user-456" });
  });

  // Feature: Expose the authenticated user identity | Scenario: Authenticated request contains the full identity context
  it("exposes uid and claims on the request", async () => {
    const app = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    await request(app)
      .get("/identity")
      .set("Authorization", "Bearer token-tenant")
      .expect(200, { uid: "user-789", roles: ["admin"], tenant: "tenant-42" });
  });
});

describe("integration: fail fast when auth infrastructure is not initialized", () => {
  // Feature: Fail fast when authentication infrastructure is not initialized | Scenario: Authentication fails when identity verification is not available
  it("returns a configuration error when auth client is unavailable", async () => {
    Object.defineProperty(admin, "auth", {
      value: () => {
        throw new Error("not initialized");
      },
      configurable: true,
    });

    const app = buildApp({ authClient: undefined, useRoleHandler: false });

    await request(app)
      .get("/protected")
      .set("Authorization", "Bearer token-user")
      .expect(500, { error: "Auth infrastructure not initialized" });
  });
});

describe("integration: work consistently across environments", () => {
  // Feature: Work consistently across environments | Scenario: Local environment behaves the same as production
  it("behaves the same using injected auth client and default admin auth", async () => {
    const injectedApp = buildApp({ authClient: createInMemoryAuthClient(tokens) });

    const injectedResponse = await request(injectedApp)
      .get("/protected")
      .set("Authorization", "Bearer token-user");

    Object.defineProperty(admin, "auth", {
      value: () => createInMemoryAuthClient(tokens),
      configurable: true,
    });

    const defaultApp = buildApp({ authClient: undefined });

    const defaultResponse = await request(defaultApp)
      .get("/protected")
      .set("Authorization", "Bearer token-user");

    assert.strictEqual(injectedResponse.status, defaultResponse.status);
    assert.deepStrictEqual(injectedResponse.body, defaultResponse.body);
  });
});
