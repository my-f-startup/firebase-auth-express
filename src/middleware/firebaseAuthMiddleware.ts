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
};

const resolveAuthClient = (options: FirebaseAuthMiddlewareOptions): AuthClient | undefined => {
  if (options.authClient) return options.authClient;

  try {
    return admin.auth();
  } catch {
    return undefined;
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

    try {
      const decoded = await authClient.verifyIdToken(token);
      if (!decoded?.uid) {
        res.status(401).json({ error: "Invalid token" });
        return;
      }

      req.auth = { uid: decoded.uid, token: decoded };
      next();
    } catch {
      res.status(401).json({ error: "Invalid token" });
    }
  };

  return handler;
};
