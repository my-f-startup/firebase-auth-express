# firebase-auth-express

Zero-trust Firebase Authentication middleware for Express.js.

Express middleware and guards for Firebase Authentication. Validates ID tokens, exposes the authenticated user context to handlers, and enforces role-based access control. Includes unit, integration (in-memory), and E2E tests with Firebase Auth emulator via Testcontainers.

---

## Why this exists

Firebase Authentication provides secure identity tokens, but most Express applications end up repeating the same boilerplate in every route:

- Extracting `Authorization: Bearer <token>`
- Calling `verifyIdToken`
- Handling missing or invalid tokens
- Propagating `uid` and token claims
- Enforcing role-based access
- Mocking authentication in tests
- Integrating with the Firebase Auth emulator

This package centralizes those concerns into a **single, composable, and testable authentication layer**, so your handlers can focus purely on business logic.

---

## Features

- **Zero-trust authentication** – Validates Firebase ID tokens on every request
- **Typed identity context** – Populates `req.auth` with `uid` and token claims
- **Role-based authorization** – `requireRole` enforces custom-claim roles
- **Composable guards** – Clear separation between authentication and authorization
- **Emulator-first testing** – Unit, integration, and E2E tests using Firebase Auth emulator

---

## Installation

```bash
npm install @my-f*-startup/firebase-auth-express
```

---

## Quick Start (dev)

```ts
import express from "express";
import admin from "firebase-admin";
import {
  firebaseAuthMiddleware,
  requireAuth,
  requireRole,
} from "@my-f*-startup/firebase-auth-express";

admin.initializeApp({ projectId: "demo-project" });

const app = express();
app.use(express.json());

// Global authentication middleware
app.use(firebaseAuthMiddleware());

app.get(
  "/me",
  requireAuth((req, res) => {
    res.json({ uid: req.auth!.uid });
  })
);

app.get(
  "/admin",
  requireRole("admin", (req, res) => {
    res.json({ uid: req.auth!.uid });
  })
);

app.listen(3000, () => console.log("listening on http://localhost:3000"));
```

---

## Mental model

This package separates authentication concerns into two layers:

### 1. Middleware

- `firebaseAuthMiddleware`
- Runs once per request
- Extracts and validates the Firebase ID token
- Populates `req.auth`

### 2. Guards

- `requireAuth`
- `requireRole`
- Applied per-route
- Enforce access rules before executing handlers

This model keeps authentication logic centralized and routes clean.

---

## Using the Firebase Auth Emulator

When using the Firebase Auth emulator locally:

```bash
export FIREBASE_AUTH_EMULATOR_HOST=localhost:9099
export GCLOUD_PROJECT=demo-project
```

The `firebase-admin` SDK automatically routes authentication calls to the emulator when `FIREBASE_AUTH_EMULATOR_HOST` is set.

---

## API

### `firebaseAuthMiddleware(options?)`

Factory that returns an Express middleware. It:

- Requires `Authorization: Bearer <token>`
- Calls `admin.auth().verifyIdToken(token)`
- Sets `req.auth = { uid, token }`
- Returns `401` on missing or invalid token
- Returns `500` if the auth infrastructure is not initialized

You can inject a custom auth client for tests:

```ts
firebaseAuthMiddleware({
  authClient: {
    verifyIdToken: async (token) => ({ uid: "user-1" } as any),
  },
});
```

---

### `requireAuth(handler)`

Ensures that the request is authenticated before executing the handler.

- Returns `401` if `req.auth` is missing

---

### `requireRole(role | roles[], handler)`

Ensures the authenticated user has the required role(s), as defined in Firebase custom claims.

- Returns `401` if `req.auth` is missing
- Returns `403` if required role(s) are not present in `req.auth.token.roles`

---

## Security model

- Stateless authentication
- No sessions
- No token caching
- Every request validates its Firebase ID token
- Authorization is based exclusively on verified token claims

This design favors correctness and security over performance shortcuts.

---

## Testing philosophy

This package treats the Firebase Auth emulator as a first-class dependency.

- **Unit tests** – Pure logic
- **Integration tests** – In-memory auth clients
- **E2E tests** – Real Firebase Auth emulator via Testcontainers

This ensures production-like behavior without external dependencies.

---

## Tests

- Unit: `npm run test:unit`
- Integration (in-memory): `npm run test:int`
- E2E (Auth emulator): `npm run test:e2e`
- All tests: `npm test`

---

## Build & Runtime

- Dev: `npm start` (tsx)
- Build JS: `npm run build` (outputs `dist/`)

---

## Compatibility

- Node.js: >= 20
- Firebase Admin SDK: `firebase-admin`

---

## Non-goals

- User management
- Session handling
- Token refresh
- OAuth flows

This package focuses strictly on **request authentication and authorization**.
