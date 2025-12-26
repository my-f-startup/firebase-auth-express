import type { Request } from "express";
import { DecodedIdToken } from "firebase-admin/auth";
import { AuthClaims } from "./AuthClaims";

export interface AuthenticatedRequest extends Request {
  auth?: {
    uid: string;
    token: DecodedIdToken & AuthClaims;
  };
}
