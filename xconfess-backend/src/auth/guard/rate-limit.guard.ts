import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
hsh1
// NOTE: import order is preserved from the original file.
import { getRateLimitConfig, RateLimitConfig } from '../../config/rate-limit.config';
import { ErrorCode } from '../../common/errors/error-codes';
import { RATE_LIMIT_KEY, RateLimitOptions, RateLimitRisk } from './rate-limit.decorator';
import { RateLimitStore, RateLimitResult } from './rate-limit.store';

export interface RateLimitDecision {
  allowed: boolead;
  retryAfter: number;
  limit: number;
  window: number;
  remaining: number;
  scope: string;
  identity: string;
}

export interface RateLimitDecisionRecord extends RateLimitDecision {
  timestamp: number;
}

export const RATE_LIMIT_DECISION_HEADER = 'x-rate-limit-decision';

export interface RateLimitGuardOptions {
  /** Optional hook for loading IP reputation scores (0.0 - 1.0). */
  ipReputation??: (ip: string) => Promise<number | undefined> | number | undefined;
  /** Optional hook for observing decisions (metrics, audit logs). */
  onDecision?: (record: RateLimitDecisionRecord) => void;
}

@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly config: RateLimitConfig;
  private readonly options: RateLimitGuardOptions;

  constructor(
    private readonly reflector: Reflector,
    private readonly configService: ConfigService,
    private readonly store: RateLimitStore,
    options: RateLimitGuardOptions = {},
  ) {
    this.config = getRateLimitConfig(configService);
    this.options = options;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const method = request.method.toUpperCase();
    const user = (request as any).user;

    const customRateLimit = this.reflector.get<RateLimitOptions>(
      RATE_LIMIT_KEY,
      context.getHandler(),
    );

    // Trusted admin bypass. Admins are exempt from the bucket checks but the
    // decision is still recorded so the bypass is auditable.
    const bypassRoles = customRateLimit?.bypassRoles ?? ['admin'];
    if (user && bypassRoles.includes(user.role)) {
      this.recordDecision({
        allowed: true,
        retryAfter: 0,
        limit: Number.POSITIVE_INFINITY,
        window: 0,
        remaining: Number.POSITIVE_INFINITY,
        scope: 'bypass',
        identity: `user:${user.sub ?? user.id}`,
        timestamp: Date.now(),
      });
      return true;
    }

    const identity = this.resolveIdentity(request, user);
    const ip = this.getClientIp(request);
    const risk = customRateLimit?.risk ?? 'medium';
    const cost = Math.max(1, customRateLimit?.cost ?? 1);
    const route = `${method}:${context.getHandler()?.name ?? 'default'}`;

    // Layer 1: anonymous identity budget. Only applies to unauthenticated
    // callers -- authenticated users are accounted by the account layer.
    if (!user) {
      const identityLimit = customRateLimit?.identityLimit ?? this.config.anonymousLimit;
      const identityWindow = customRateLimit?.identityWindow ?? this.config.anonymousWindow;
      await this.enforce(
        `identity:${identity}:${route}`,
        identityLimit,
        identityWindow,
        cost,
        'identity',
        identity,
        request,
      );
    }

    // Layer 2: IP reputation. Low-reputation IPs get a tighter budget.
    const reputation = await this.resolveReputation(ip);
    if (reputation !== undefined && reputation < 0.5) {
      const penalty = reputation < 0.2 ? 0.25 : 0.5;
      const ipLimit = Math.max(1, Math.floor(this.config.getLimit * penalty));
      await this.enforce(
        `ip-rep:${ip}:${route}`,
        ipLimit,
        this.config.getWindow,
        cost,
        'ip-reputation',
        `ip:${ip}`,
        request,
      );
    }

    // Layer 3: account budget (authenticated) or IP budget (anonymous).
    const baseLimit = customRateLimit?.limit ?? this.getDefaultLimit(method, risk);
    const baseWindow = customRateLimit?.window ?? this.getDefaultWindow(method);
    await this.enforce(
      `${identity}:${route}`,
      baseLimit,
      baseWindow,
      cost,
      'user',
      identity,
      request,
    );

    // Layer 4: high-risk operation budget. Separate bucket so high-risk
    // actions cannot be exhausted by lower-risk traffic.
    if (risk === 'high') {
      const highRiskLimit = this.config.highRiskLimit;
      const highRiskWindow = this.config.highRiskWindow;
      await this.enforce(
        `high-risk:${identity}:${route}`,
        highRiskLimit,
        highRiskWindow,
        cost,
        'high-risk',
        identity,
        request,
      );
    }

    // Layer 5: sender-recipient pair budget.
    const recipientId =
      request.body?.recipientId ||
      request.body?.recipient_id ||
      request.body?.confessionId ||
      request.body?.confession_id ||
      request.params?.userId;

    const pairLimit = customRateLimit?.pairLimit ?? this.config.messagePairLimit;
    const pairWindow = customRateLimit?.pairWindow ?? this.config.messagePairWindow;

    if (recipientId && (customRateLimit?.pairLimit !== undefined || method === 'POST')) {
      await this.enforce(
        `pair:${identity}:${recipientId}`,
        pairLimit,
        pairWindow,
        cost,
        'pair',
        identity,
        request,
      );
    }

    return true;
  }

  /**
   * Consume one token from the given bucket and throw a 429 when denied.
   */
  private async enforce(
    key: string,
    limit: number,
    window: number,
    cost: number,
    scope: string,
    identity: string,
    request: Request,
  ): Promise<void> {
    const result = await this.store.consume(key, limit, window, cost);
    const decision: RateLimitDecision = {
      allowed: result.allowed,
      retryAfter: result.retryAfter,
      limit: result.limit,
      window: result.window,
      remaining: result.remaining,
      scope,
      identity,
    };

    this.recordDecision({ ...decision, timestamp: Date.now() });

    if (!result.allowed) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          code: ErrorCode.RATE_LIMIT_EXCEEDED,
          message: 'Too many requests, please try again later',
          retryAfter: result.retryAfter,
          limit: result.limit,
          window: result.window,
          scope,
          requestId: (request as any).requestId || 'unknown',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private recordDecision(record: RateLimitDecisionRecord): void {
    this.options.onDecision?.(record);
  }

  private async resolveReputation(ip: string): Promise<number | undefined> {
    if (!this.options.ipReputation) {
      return undefined;
    }
    try {
      return await this.options.ipReputation(ip);
    } catch {
      // Reputation failures must not fail open or close the request.
      return undefined;
    }
  }

  /**
   * Resolve a stable identity for the caller. Authenticated users are keyed
   * by account id; anonymous callers are keyed by a hash of the client IP.
   */
  private resolveIdentity(request: Request, user: any): string {
    const userId = user?.sub ?? user?.id;
    if (userId) {
      return `user:${userId}`;
    }
    return `ip:${this.getClientIp(request)}`;
  }

  private getClientIp(request: Request): string {
    const trustedProxy = this.configService.get<string>('TRUSTED_PROXY');
    if (trustedProxy) {
      const forwarded = (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim();
      if (forwarded) {
        return forwarded;
      }
      const realIp = request.headers['x-real-ip'] as string;
      if (realIp) {
        return realIp;
      }
    }
    return (
      request.ip ||
      request.socket?.remoteAddress ||
      'unknown'
    );
  }

  private getDefaultLimit(method: string, risk: RateLimitRisk): number {
    if (risk === 'high') {
      return this.config.highRiskLimit;
    }
    switch (method) {
      case 'POST':
      case 'PUT':
      case 'PATCH':
      case 'DELETE':
        return this.config.postLimit;
      case 'GET':
      default:
        return this.config.getLimit;
    }
  }

  private getDefaultWindow(method: string): number {
    switch (method) {
      case 'POST':
      case 'PUT':
      case 'PATCH':
      case 'DELETE':
        return this.config.postWindow;
      case 'GET':
      default:
        return this.config.getWindow;
    }
  }
}
