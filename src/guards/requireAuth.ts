import type { RequestHandler, Response, NextFunction } from "express";
import { AuthenticatedRequest } from "../types/AuthenticatedRequest";

export function requireAuth(
  handler: (req: AuthenticatedRequest, res: Response, next: NextFunction) => any
): RequestHandler {
  return (req, res, next) => {
    if (!(req as AuthenticatedRequest).auth?.uid) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    return handler(req as AuthenticatedRequest, res, next);
  };
}
