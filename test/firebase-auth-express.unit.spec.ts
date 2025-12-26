import assert from "node:assert";
import { afterEach, describe, it } from "node:test";
import express from "express";
import request from "supertest";
import admin from "firebase-admin";
import { firebaseAuthMiddleware } from "../src/middleware/firebaseAuthMiddleware";
import { requireAuth } from "../src/guards/requireAuth";
import { requireRole } from "../src/guards/requireRole";
import { AuthenticatedRequest } from "../src/types/AuthenticatedRequest";
import { Role } from "../src/types/Roles";
import { DecodedIdToken } from "firebase-admin/auth";

type FakeAuthClient = {
  verifyIdToken: (token: string) => Promise<DecodedIdToken & { roles?: Role[]; tenant?: string }>;
};

const makeToken = (
  overrides: Partial<DecodedIdToken> & { uid?: string; roles?: Role[]; tenant?: string } = {}
) =>
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
  } as DecodedIdToken & { roles?: Role[]; tenant?: string });

const seedAuth =
  (auth?: AuthenticatedRequest["auth"]) =>
  (req: express.Request, _res: express.Response, next: express.NextFunction) => {
    if (auth) {
      (req as AuthenticatedRequest).auth = auth;
    }
    next();
  };

const buildApp = (configure: (app: express.Express) => void) => {
  const app = express();
  app.use(express.json());
  configure(app);
  return app;
};

const originalAdminAuth = admin.auth;

afterEach(() => {
  Object.defineProperty(admin, "auth", { value: originalAdminAuth, configurable: true });
});

describe("firebaseAuthMiddleware", () => {
  // Feature: Authenticate incoming requests | Scenario: Request with a valid identity token is accepted
  it("accepts a valid identity token and exposes uid", async () => {
    const authClient: FakeAuthClient = {
      verifyIdToken: async () => makeToken({ uid: "user-123", roles: ["user"], tenant: "tenant-1" }),
    };

    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient }));
      app.get("/protected", (req, res) => {
        const auth = (req as AuthenticatedRequest).auth!;
        res.json({ uid: auth.uid });
      });
    });

    await request(app)
      .get("/protected")
      .set("Authorization", "Bearer token-abc")
      .expect(200, { uid: "user-123" });
  });

  // Feature: Authenticate incoming requests | Scenario: Request without an identity token is rejected
  it("rejects requests without an identity token", async () => {
    const authClient: FakeAuthClient = { verifyIdToken: async () => makeToken({ uid: "user-123" }) };
    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient }));
      app.get("/protected", (_req, res) => res.json({ ok: true }));
    });

    await request(app).get("/protected").expect(401, { error: "Unauthorized" });
  });

  // Feature: Authenticate incoming requests | Extra: malformed authorization header
  it("rejects malformed authorization headers", async () => {
    const authClient: FakeAuthClient = { verifyIdToken: async () => makeToken({ uid: "user-123" }) };
    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient }));
      app.get("/protected", (_req, res) => res.json({ ok: true }));
    });

    await request(app).get("/protected").set("Authorization", "Token token-abc").expect(401, {
      error: "Unauthorized",
    });
  });

  // Feature: Authenticate incoming requests | Extra: invalid token
  it("returns 401 when token verification fails", async () => {
    const authClient: FakeAuthClient = {
      verifyIdToken: async () => {
        throw new Error("invalid");
      },
    };
    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient }));
      app.get("/protected", (_req, res) => res.json({ ok: true }));
    });

    await request(app).get("/protected").set("Authorization", "Bearer bad").expect(401, {
      error: "Invalid token",
    });
  });

  // Feature: Authenticate incoming requests | Extra: token without uid
  it("returns 401 when verification succeeds without uid", async () => {
    const authClient: FakeAuthClient = {
      verifyIdToken: async () => makeToken({ uid: "" }),
    };
    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient }));
      app.get("/protected", (_req, res) => res.json({ ok: true }));
    });

    await request(app).get("/protected").set("Authorization", "Bearer bad").expect(401, {
      error: "Invalid token",
    });
  });

  // Feature: Fail fast when authentication infrastructure is not initialized | Scenario: Authentication fails when identity verification is not available
  it("fails fast when auth infrastructure is not initialized", async () => {
    Object.defineProperty(admin, "auth", {
      value: () => {
        throw new Error("not initialized");
      },
      configurable: true,
    });

    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware());
      app.get("/protected", (_req, res) => res.json({ ok: true }));
    });

    await request(app).get("/protected").set("Authorization", "Bearer any").expect(500, {
      error: "Auth infrastructure not initialized",
    });
  });

  // Feature: Work consistently across environments | Scenario: Local environment behaves the same as production
  it("behaves consistently with injected auth client and default admin auth", async () => {
    const injectedClient: FakeAuthClient = {
      verifyIdToken: async () => makeToken({ uid: "user-789", roles: ["user"] }),
    };
    const injectedApp = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient: injectedClient }));
      app.get("/whoami", (req, res) => {
        const auth = (req as AuthenticatedRequest).auth!;
        res.json({ uid: auth.uid });
      });
    });

    await request(injectedApp)
      .get("/whoami")
      .set("Authorization", "Bearer ok")
      .expect(200, { uid: "user-789" });

    Object.defineProperty(admin, "auth", {
      value: () =>
        ({
          verifyIdToken: async () => makeToken({ uid: "user-789", roles: ["user"] }),
        } as unknown),
      configurable: true,
    });

    const defaultApp = buildApp((app) => {
      app.use(firebaseAuthMiddleware());
      app.get("/whoami", (req, res) => {
        const auth = (req as AuthenticatedRequest).auth!;
        res.json({ uid: auth.uid });
      });
    });

    await request(defaultApp)
      .get("/whoami")
      .set("Authorization", "Bearer ok")
      .expect(200, { uid: "user-789" });
  });

  // Feature: Expose the authenticated user identity | Scenario: Access the authenticated user identifier
  it("exposes uid on the request", async () => {
    const authClient: FakeAuthClient = {
      verifyIdToken: async () => makeToken({ uid: "user-456" }),
    };

    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient }));
      app.get("/identity", (req, res) => {
        const auth = (req as AuthenticatedRequest).auth!;
        res.json({ uid: auth.uid, roles: auth.token.roles, tenant: auth.token.tenant });
      });
    });

    await request(app)
      .get("/identity")
      .set("Authorization", "Bearer ok")
      .expect(200, { uid: "user-456" });
  });

  // Feature: Expose the authenticated user identity | Scenario: Authenticated request contains the full identity context
  it("exposes full identity context to handlers", async () => {
    const authClient: FakeAuthClient = {
      verifyIdToken: async () => makeToken({ uid: "user-789", roles: ["admin"], tenant: "tenant-42" }),
    };

    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient }));
      app.get("/identity", (req, res) => {
        const auth = (req as AuthenticatedRequest).auth!;
        res.json({ uid: auth.uid, roles: auth.token.roles, tenant: auth.token.tenant });
      });
    });

    await request(app)
      .get("/identity")
      .set("Authorization", "Bearer ok")
      .expect(200, { uid: "user-789", roles: ["admin"], tenant: "tenant-42" });
  });
});

describe("requireAuth", () => {
  // Feature: Protect handlers that require authentication | Scenario: Protected operation is executed by an authenticated user
  it("executes handler when authenticated", async () => {
    const app = buildApp((app) => {
      app.use(seedAuth({ uid: "user-321", token: {} as any }));
      app.get(
        "/protected",
        requireAuth((req, res) => {
          res.json({ uid: req.auth!.uid });
        })
      );
    });

    await request(app).get("/protected").expect(200, { uid: "user-321" });
  });

  // Feature: Protect handlers that require authentication | Scenario: Protected operation is blocked for unauthenticated requests
  it("blocks unauthenticated requests", async () => {
    const app = buildApp((app) => {
      app.get(
        "/protected",
        requireAuth((_req, res) => {
          res.json({ ok: true });
        })
      );
    });

    await request(app).get("/protected").expect(401, { error: "Unauthorized" });
  });
});

describe("requireRole", () => {
  // Feature: Authorize access based on user roles | Scenario: User with required role can access the operation
  it("allows access when the required role is present", async () => {
    const app = buildApp((app) => {
      app.use(seedAuth({ uid: "admin-001", token: { roles: ["admin"] } as any }));
      app.get(
        "/admin",
        requireRole("admin", (req, res) => {
          res.json({ uid: req.auth!.uid });
        })
      );
    });

    await request(app).get("/admin").expect(200, { uid: "admin-001" });
  });

  // Feature: Authorize access based on user roles | Scenario: User without required role cannot access the operation
  it("blocks when required role is missing", async () => {
    const app = buildApp((app) => {
      app.use(seedAuth({ uid: "user-002", token: { roles: ["user"] } as any }));
      app.get(
        "/admin",
        requireRole("admin", (_req, res) => {
          res.json({ ok: true });
        })
      );
    });

    await request(app).get("/admin").expect(403, { error: "Forbidden" });
  });

  // Feature: Authorize access based on user roles | Scenario Outline: User with any allowed role can access the operation | Examples: admin-003, support-007
  it("allows access when any allowed role matches", async () => {
    const examples: Array<{ uid: string; role: Role }> = [
      { uid: "admin-003", role: "admin" },
      { uid: "support-007", role: "support" },
    ];

    for (const example of examples) {
      const app = buildApp((app) => {
        app.use(seedAuth({ uid: example.uid, token: { roles: [example.role] } as any }));
        app.get(
          "/restricted",
          requireRole(["admin", "support"], (req, res) => {
            res.json({ uid: req.auth!.uid });
          })
        );
      });

      await request(app)
        .get("/restricted")
        .expect(200, { uid: example.uid });
    }
  });

  // Feature: Reject access when role information is missing | Scenario: User without role information cannot access a role-protected operation
  it("rejects when role information is missing", async () => {
    const app = buildApp((app) => {
      app.use(seedAuth({ uid: "user-999", token: {} as any }));
      app.get(
        "/role-protected",
        requireRole("admin", (_req, res) => {
          res.json({ ok: true });
        })
      );
    });

    await request(app).get("/role-protected").expect(403, { error: "Forbidden" });
  });

  // Feature: Compose authentication and authorization rules | Scenario: Authentication is checked before role authorization
  it("runs authentication before role authorization", async () => {
    let roleChecked = false;

    const app = buildApp((app) => {
      app.use(
        firebaseAuthMiddleware({
          authClient: {
            verifyIdToken: async () => makeToken({ uid: "user-abc", roles: [] }),
          },
        })
      );
      app.get(
        "/role-first",
        requireRole("admin", (_req, res) => {
          roleChecked = true;
          res.json({ ok: true });
        })
      );
    });

    const response = await request(app).get("/role-first");
    assert.strictEqual(response.status, 401);
    assert.strictEqual(response.body.error, "Unauthorized");
    assert.strictEqual(roleChecked, false);
  });

  // Feature: Compose authentication and authorization rules | Extra: role authorization after authentication
  it("returns forbidden when authenticated but missing required role", async () => {
    const app = buildApp((app) => {
      app.use(
        firebaseAuthMiddleware({
          authClient: {
            verifyIdToken: async () => makeToken({ uid: "user-abc", roles: [] }),
          },
        })
      );
      app.get(
        "/role-first",
        requireRole("admin", (_req, res) => {
          res.json({ ok: true });
        })
      );
    });

    await request(app)
      .get("/role-first")
      .set("Authorization", "Bearer valid")
      .expect(403, { error: "Forbidden" });
  });
});
