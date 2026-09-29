import { SetMetadata } from '@nestjs/common';

export const RATE_LIMIT_KEY = 'rateLimit';

/**
 * Operation risk classes. High-risk operations get their own budgets so that a
 * burst of low-risk traffic cannot exhaust the budget for sensitive actions.
 */
export type RateLimitRisk = 'low' | 'medium' | 'high';

/**
 * Options for the RateLimit decorator.
 *
 * - limit / window: per-sender budget (window in seconds).
 * - pairLimit / pairWindow: optional sender-recipient budget.
 * - risk: operation risk class used to derive a high-risk budget.
 * - identityLimit / identityWindow: optional anonymous-identity budget.
 * - bypassRoles: roles (e.g. admin) that skip this limit entirely.
 * - cost: relative cost of the operation; consumes this many tokens.
 */
export interface RateLimitOptions {
  limit: number;
  window: number; // in seconds
  pairLimit?: number;
  pairWindow?: number;
  risk?: RateLimitRisk;
  identityLimit?: number;
  identityWindow?: number;
  bypassRoles?: string[];
  cost?: number;
}

export const RateLimit = (
  limit: number,
  window: number,
  pairLimit?: number,
  pairWindow?: number,
  extra?: Pick<RateLimitOptions, 'risk' | 'identityLimit' | 'identityWindow' | 'bypassRoles' | 'cost'>,
) =>
  SetMetadata(RATE_LIMIT_KEY, {
    limit,
    window,
    pairLimit,
    pairWindow,
    ...(extra ?? {}),
  } as RateLimitOptions);
