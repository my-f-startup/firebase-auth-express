import { Role } from "./Roles";

export interface AuthClaims {
  roles?: Role[];
  tenant?: string;
}
