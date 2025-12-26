import type { RequestHandler, Response, NextFunction } from "express";
import { Role } from "../types/Roles";
import { AuthenticatedRequest } from "../types/AuthenticatedRequest";

export function requireRole(
  required: Role | Role[],
  handler: (req: AuthenticatedRequest, res: Response, next: NextFunction) => any
): RequestHandler {
  const roles = Array.isArray(required) ? required : [required];

  return (req, res, next) => {
    const authReq = req as AuthenticatedRequest;
    if (!authReq.auth?.uid) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const userRoles = authReq.auth.token.roles ?? [];

    if (!roles.some(r => userRoles.includes(r))) {
      return res.status(403).json({ error: "Forbidden" });
    }

    return handler(authReq, res, next);
  };
}
