import assert from "node:assert";
import { after, afterEach, before, describe, it } from "node:test";
import path from "node:path";
import express from "express";
import request from "supertest";
import admin from "firebase-admin";
import { GenericContainer, Wait } from "testcontainers";
import { firebaseAuthMiddleware } from "../src/middleware/firebaseAuthMiddleware";
import { requireAuth } from "../src/guards/requireAuth";
import { requireRole } from "../src/guards/requireRole";
import { AuthenticatedRequest } from "../src/types/AuthenticatedRequest";

const projectId = "demo-project";

const buildApp = ({
  withRoles = true,
  initializeAdmin = true,
}: {
  withRoles?: boolean;
  initializeAdmin?: boolean;
} = {}) => {
  if (initializeAdmin) {
    ensureAdmin();
  }

  const app = express();
  app.use(express.json());
  app.use(firebaseAuthMiddleware());

  app.get(
    "/protected",
    requireAuth((req, res) => {
      res.json({ uid: req.auth!.uid });
    })
  );

  if (withRoles) {
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

let emulator: import("testcontainers").StartedTestContainer | null = null;
let emulatorHost = "";
let emulatorPort = 0;

const emulatorUrl = () => `http://${emulatorHost}:${emulatorPort}`;

const startEmulator = async () => {
  const built = await GenericContainer.fromDockerfile(
    path.join(process.cwd(), "test", "firebase"),
    "Dockerfile.firebase"
  ).build();

  const container = await built
    .withExposedPorts(4000, 9099)
    .withBindMounts([
      {
        source: path.join(process.cwd(), "test", "firebase", "firebase.json"),
        target: "/app/firebase.json",
        mode: "ro" as const,
      },
      {
        source: path.join(process.cwd(), "test", "firebase", ".firebaserc"),
        target: "/app/.firebaserc",
        mode: "ro" as const,
      },
    ])
    .withEnvironment({ FIREBASE_PROJECT_ID: projectId })
    .withWaitStrategy(Wait.forHealthCheck())
    .start();

  emulatorHost = container.getHost();
  emulatorPort = container.getMappedPort(9099);

  process.env.FIREBASE_AUTH_EMULATOR_HOST = `${emulatorHost}:${emulatorPort}`;
  process.env.GCLOUD_PROJECT = projectId;
  return container;
};

const resetAuthEmulator = async () => {
  const res = await fetch(
    `${emulatorUrl()}/emulator/v1/projects/${projectId}/accounts`,
    {
      method: "DELETE",
    }
  );
  assert.strictEqual(res.ok, true);
};

const ensureAdmin = () => {
  if (!admin.apps.length) {
    admin.initializeApp({ projectId });
  }
  return admin.auth();
};

const signUp = async (email: string, password: string) => {
  const res = await fetch(
    `${emulatorUrl()}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password, returnSecureToken: true }),
    }
  );
  assert.strictEqual(res.ok, true);
  return (await res.json()) as { localId: string };
};

const signInWithPassword = async (email: string, password: string) => {
  const res = await fetch(
    `${emulatorUrl()}/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=fake-api-key`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password, returnSecureToken: true }),
    }
  );
  assert.strictEqual(res.ok, true);
  return (await res.json()) as { idToken: string };
};

const createUserWithClaims = async ({
  email,
  password,
  claims,
}: {
  email: string;
  password: string;
  claims?: Record<string, unknown>;
}) => {
  const { localId } = await signUp(email, password);
  const auth = ensureAdmin();
  if (claims) {
    await auth.setCustomUserClaims(localId, claims);
  }
  const { idToken } = await signInWithPassword(email, password);
  return { uid: localId, idToken };
};

before(async () => {
  emulator = await startEmulator();
});

after(async () => {
  if (emulator) {
    await emulator.stop();
  }
});

afterEach(async () => {
  await resetAuthEmulator();
  await Promise.all(admin.apps.map((app) => app.delete()));
});

describe("e2e: authenticate incoming requests", () => {
  it("accepts a request with a valid identity token", async () => {
    const { uid, idToken } = await createUserWithClaims({
      email: "user-123@example.com",
      password: "password123",
    });
    const app = buildApp();

    await request(app)
      .get("/protected")
      .set("Authorization", `Bearer ${idToken}`)
      .expect(200, { uid });
  });

  it("rejects requests without an identity token", async () => {
    const app = buildApp();

    await request(app).get("/protected").expect(401, { error: "Unauthorized" });
  });
});

describe("e2e: protect handlers that require authentication", () => {
  it("executes protected handler for authenticated user", async () => {
    const { uid, idToken } = await createUserWithClaims({
      email: "user-321@example.com",
      password: "password321",
    });
    const app = buildApp();

    await request(app)
      .get("/protected")
      .set("Authorization", `Bearer ${idToken}`)
      .expect(200, { uid });
  });

  it("blocks unauthenticated access to protected handler", async () => {
    const app = buildApp();

    await request(app).get("/protected").expect(401, { error: "Unauthorized" });
  });
});

describe("e2e: authorize access based on user roles", () => {
  it("allows user with required role", async () => {
    const { uid, idToken } = await createUserWithClaims({
      email: "admin-001@example.com",
      password: "password-admin",
      claims: { roles: ["admin"] },
    });
    const app = buildApp();

    await request(app)
      .get("/admin")
      .set("Authorization", `Bearer ${idToken}`)
      .expect(200, { uid });
  });

  it("blocks user without required role", async () => {
    const { idToken } = await createUserWithClaims({
      email: "user-002@example.com",
      password: "password-user",
      claims: { roles: ["user"] },
    });
    const app = buildApp();

    await request(app)
      .get("/admin")
      .set("Authorization", `Bearer ${idToken}`)
      .expect(403, { error: "Forbidden" });
  });

  it("allows access when any allowed role matches", async () => {
    const { uid, idToken } = await createUserWithClaims({
      email: "support-007@example.com",
      password: "password-support",
      claims: { roles: ["support"] },
    });
    const app = buildApp();

    await request(app)
      .get("/support-or-admin")
      .set("Authorization", `Bearer ${idToken}`)
      .expect(200, { uid });
  });
});

describe("e2e: reject access when role information is missing", () => {
  it("blocks role-protected operations when roles are absent", async () => {
    const { idToken } = await createUserWithClaims({
      email: "user-999@example.com",
      password: "password-999",
    });
    const app = buildApp();

    await request(app)
      .get("/admin")
      .set("Authorization", `Bearer ${idToken}`)
      .expect(403, { error: "Forbidden" });
  });
});

describe("e2e: compose authentication and authorization", () => {
  it("rejects unauthenticated requests before role checks", async () => {
    let roleChecked = false;
    const app = buildApp({ withRoles: false });
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

  it("authorizes only after successful authentication", async () => {
    const { idToken } = await createUserWithClaims({
      email: "user-no-role@example.com",
      password: "password-no-role",
    });
    const app = buildApp({ withRoles: false });
    app.get(
      "/role-first",
      requireRole("admin", (_req, res) => {
        res.json({ ok: true });
      })
    );

    await request(app)
      .get("/role-first")
      .set("Authorization", `Bearer ${idToken}`)
      .expect(403, { error: "Forbidden" });
  });
});

describe("e2e: expose authenticated user identity", () => {
  it("exposes uid and claims on the request", async () => {
    const { uid, idToken } = await createUserWithClaims({
      email: "user-456@example.com",
      password: "password-456",
      claims: { roles: ["admin"], tenant: "tenant-42" },
    });
    const app = buildApp();

    await request(app)
      .get("/identity")
      .set("Authorization", `Bearer ${idToken}`)
      .expect(200, { uid, roles: ["admin"], tenant: "tenant-42" });
  });
});

describe("e2e: fail fast when auth infrastructure is not initialized", () => {
  it("returns a configuration error when auth client is unavailable", async () => {
    await Promise.all(admin.apps.map((app) => app.delete()));
    const app = buildApp({ initializeAdmin: false });

    await request(app)
      .get("/protected")
      .set("Authorization", "Bearer any")
      .expect(500, { error: "Auth infrastructure not initialized" });
  });
});

describe("e2e: work consistently across environments", () => {
  it("behaves the same using emulator and default auth client", async () => {
    const { uid, idToken } = await createUserWithClaims({
      email: "user-789@example.com",
      password: "password-789",
      claims: { roles: ["user"] },
    });
    const app = buildApp();

    const res = await request(app)
      .get("/protected")
      .set("Authorization", `Bearer ${idToken}`);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.uid, uid);
  });
});
