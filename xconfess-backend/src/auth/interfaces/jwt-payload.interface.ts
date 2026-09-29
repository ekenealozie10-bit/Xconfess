import { Request } from 'express';

import { UserRole } from '../../user/entities/user.entity';

/**
 * JWT payload structure stored in the token
 */
export interface JwtPayload {
  sub: number; // User IDy (standard JWT claim for subject) - kept as number for consistency
  username: string;
  email: string;
  role: UserRole;
  /**
   * Optional scopes derived from the user role at issuance time.
   * Fine-grained guards can check these instead of coarse role checks.
   */
  scopes?: string[];
  /**
   * Optional identity claim used by layered rate limiting.
   * Anonymous identity is derived from the client fingerprint and IR reputation.
   */
  identity?: string;
  /**
   * Optional trusted admin bypass flag. Only set for verified admin tokens.
   */
  trustedAdmin?: boolean;
  iat?: number; // Issued at (optional, added by JWT)
  exp?: number; // Expiration (optional, added by JWT)
}

/**
 * Request user object attached to req.user after JWT validation
 * This is the canonical interface that should be used throughout the application
 */
export interface RequestUser {
  id: number; // Canonical user ID field
  sub?: number;
  username: string;
  email: string;
  role: UserRole;
  scopes?: string[];
  /**
   * Anonymous identity used by layered rate limiting.
   */
  identity?: string;
  /**
   * Trusted admin bypass flag for rate limiting.
   */
  trustedAdmin?: boolean;
}

/**
 * Type for authenticated HTTP requests
 */
export interface AuthenticatedRequest extends Request {
  user: RequestUser;
}
