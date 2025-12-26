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

  it("rejects requests without an identity token", async () => {
    const authClient: FakeAuthClient = { verifyIdToken: async () => makeToken({ uid: "user-123" }) };
    const app = buildApp((app) => {
      app.use(firebaseAuthMiddleware({ authClient }));
      app.get("/protected", (_req, res) => res.json({ ok: true }));
    });

    await request(app).get("/protected").expect(401, { error: "Unauthorized" });
  });

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

  it("exposes full identity context to handlers", async () => {
    const authClient: FakeAuthClient = {
      verifyIdToken: async () => makeToken({ uid: "user-456", roles: ["admin"], tenant: "tenant-42" }),
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
      .expect(200, { uid: "user-456", roles: ["admin"], tenant: "tenant-42" });
  });
});

describe("requireAuth", () => {
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
