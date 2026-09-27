import admin from "firebase-admin";
import type { Response, NextFunction, RequestHandler } from "express";
import { AuthenticatedRequest } from "../types/AuthenticatedRequest";
import { AuthClaims } from "../types/AuthClaims";
import { DecodedIdToken } from "firebase-admin/auth";

type AuthClient = {
  verifyIdToken: (token: string) => Promise<DecodedIdToken & AuthClaims>;
};

type FirebaseAuthMiddlewareOptions = {
  authClient?: AuthClient;
  /**
   * Maximum time to wait for token verification, in milliseconds.
   *
   * The underlying firebase-admin SDK call has no timeout of its own: if the
   * connection it holds to the Auth service goes silently dead (e.g. after a
   * network interruption), the call can hang indefinitely rather than
   * rejecting, leaving the request permanently unresolved.
   *
   * @default 5000
   */
  verifyTimeoutMs?: number;
};

const DEFAULT_VERIFY_TIMEOUT_MS = 5000;

class TokenVerificationTimeoutError extends Error {}

const resolveAuthClient = (options: FirebaseAuthMiddlewareOptions): AuthClient | undefined => {
  if (options.authClient) return options.authClient;

  try {
    return admin.auth();
  } catch {
    return undefined;
  }
};

const verifyIdTokenWithTimeout = async (
  authClient: AuthClient,
  token: string,
  timeoutMs: number
): Promise<DecodedIdToken & AuthClaims> => {
  let timeoutHandle: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      authClient.verifyIdToken(token),
      new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(
          () => reject(new TokenVerificationTimeoutError(`Token verification timed out after ${timeoutMs}ms`)),
          timeoutMs
        );
        timeoutHandle.unref?.();
      }),
    ]);
  } finally {
    clearTimeout(timeoutHandle);
  }
};

export const firebaseAuthMiddleware = (
  options: FirebaseAuthMiddlewareOptions = {}
): RequestHandler => {
  const handler: RequestHandler = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) => {
    const authClient = resolveAuthClient(options);
    if (!authClient) {
      res.status(500).json({ error: "Auth infrastructure not initialized" });
      return;
    }

    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer ")) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const token = header.substring("Bearer ".length);
    const timeoutMs = options.verifyTimeoutMs ?? DEFAULT_VERIFY_TIMEOUT_MS;

    try {
      const decoded = await verifyIdTokenWithTimeout(authClient, token, timeoutMs);
      if (!decoded?.uid) {
        res.status(401).json({ error: "Invalid token" });
        return;
      }

      req.auth = { uid: decoded.uid, token: decoded };
      next();
    } catch (error) {
      if (error instanceof TokenVerificationTimeoutError) {
        res.status(503).json({ error: "Auth service unavailable" });
        return;
      }
      res.status(401).json({ error: "Invalid token" });
    }
  };

  return handler;
};
