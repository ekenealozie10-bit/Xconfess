import { ExecutionContext, HttpException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { RateLimitGuard } from './rate-limit.guard';
import { RateLimitStore } from './rate-limit.store';
import { getRateLimitConfig } from '../../config/rate-limit.config';

jest.mock('../../config/rate-limit.config');

describe('RateLimitGuard', () => {
  let guard: RateLimitGuard;
  let reflector: jest.Mocked<Reflector>;
  let configService: jest.Mocked<ConfigService>;
  let store: RateLimitStore;

  const mockGetRateLimitConfig = getRateLimitConfig as jest.Mock;

  beforeEach(() => {
    reflector = {
      get: jest.fn(),
    } as unknown as jest.Mocked<Reflector>;

    configService = {
      get: jest.fn(),
    } as unknown as jest.Mocked<ConfigService>;

    mockGetRateLimitConfig.mockReturnValue({
      postLimit: 5,
      postWindow: 60,
      getLimit: 50,
      getWindow: 60,
      messageSendLimit: 10,
      messageSendWindow: 60,
      messagePairLimit: 3,
      messagePairWindow: 60,
      anonymousLimit: 50,
      anonymousWindow: 60,
      highRiskLimit: 2,
      highRiskWindow: 60,
    });

    // Real in-memory store with no Redis configured.
    configService.get.mockReturnValue(undefined);
    store = new RateLimitStore(configService);

    jest.useFakeTimers();

    guard = new RateLimitGuard(reflector, configService, store);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
  });

  const createMockExecutionContext = (
    method: string,
    ip: string,
    handler: any = () => {},
    options: { user?: any; body?: any; params?: any; headers?: any } = {},
  ): ExecutionContext => {
    return {
      switchToHttp: () => ({
        getRequest: () => ({
          method,
          ip,
          headers: options.headers || {},
          socket: { remoteAddress: ip },
          user: options.user,
          body: options.body || {},
          params: options.params || {},
        }),
      }),
      getHandler: () => handler,
    } as unknown as ExecutionContext;
  };

  it('should allow requests within the default limit', async () => {
    const context = createMockExecutionContext('GET', '127.0.0.1');
    reflector.get.mockReturnValue(undefined);

    for (let i = 0; i < 50; i++) {
      const canActivate = await guard.canActivate(context);
      expect(canActivate).toBe(true);
    }
  });

  it('should block requests exceeding the default limit', async () => {
    const context = createMockExecutionContext('POST', '127.0.0.2');
    reflector.get.mockReturnValue(undefined);

    for (let i = 0; i < 5; i++) {
      await guard.canActivate(context);
    }

    await expect(guard.canActivate(context)).rejects.toThrow(HttpException);
  });

  it('should track rate limits per authenticated user ID', async () => {
    const user1Context = createMockExecutionContext(
      'POST',
      '127.0.0.1',
      () => {},
      { user: { sub: 'user-1', role: 'user' } },
    );
    const user2Context = createMockExecutionContext(
      'POST',
      '127.0.0.1',
      () => {},
      { user: { sub: 'user-3', role: 'user' } },
    );

    reflector.get.mockReturnValue({ limit: 2, window: 60 });

    await guard.canActivate(user1Context);
    await guard.canActivate(user1Context);
    await expect(guard.canActivate(user1Context)).rejects.toThrow(HttpException);

    // User 2 from the same IP should still be allowed
    expect(await guard.canActivate(user2Context)).toBe(true);
  });

  it('should enforce sender-recipient pair rate limits', async () => {
    const contextPairA = createMockExecutionContext(
      'POST',
      '127.0.0.1',
      () => {},
      { user: { sub: 'sender-1', role: 'user' }, body: { confession_id: 'confession-A' } },
    );
    const contextPairB = createMockExecutionContext(
      'POST',
      '127.0.0.1',
      () => {},
      { user: { sub: 'sender-1', role: 'user' }, body: { confession_id: 'confession-B' } },
    );

    reflector.get.mockReturnValue({
      limit: 10,
      window: 60,
      pairLimit: 2,
      pairWindow: 60,
    });

    await guard.canActivate(contextPairA);
    await guard.canActivate(contextPairA);

    // Third send to confession-A exceeds pair limit
    await expect(guard.canActivate(contextPairA)).rejects.toThrow(HttpException);

    // Send to confession-B by same user is still under pair limit
    expect(await guard.canActivate(contextPairB)).toBe(true);
  });

  it('should return normalized 429 error structure with retry metadata', async () => {
    const context = createMockExecutionContext('POST', '127.0.0.5');
    reflector.get.mockReturnValue({ limit: 1, window: 60 });

    await guard.canActivate(context);

    try {
      await guard.canActivate(context);
      fail('Expected HttpException');
    } catch (err: any) {
      expect(err).toBeInstanceOf(HttpException);
      expect(err.getStatus()).toBe(429);
      const response = err.getResponse();
      expect(response).toMatchObject({
        statusCode: 429,
        code: 'RATE_LIMIT_EXCEEDED',
        limit: 1,
      });
      expect(typeof response.retryAfter).toBe('number');
    }
  });

  it('should not affect legitimate GET reads when POST limits are hit', async () => {
    const postContext = createMockExecutionContext('POST', '127.0.0.6');
    const getContext = createMockExecutionContext('GET', '127.0.0.6');
    reflector.get.mockReturnValue(undefined);

    for (let i = 0; i < 5; i++) {
      await guard.canActivate(postContext);
    }
    await expect(guard.canActivate(postContext)).rejects.toThrow(HttpException);

    // GET requests should still succeed
    expect(await guard.canActivate(getContext)).toBe(true);
  });

  it('should bypass the limit for trusted admin roles', async () => {
    const adminContext = createMockExecutionContext(
      'POST',
      '10.0.0.1',
      () => {},
      { user: { sub: 'admin-1', role: 'admin' } },
    );
    reflector.get.mockReturnValue({ limit: 1, window: 60 });

    for (let i = 0; i < 5; i++) {
      expect(await guard.canActivate(adminContext)).toBe(true);
    }
  });

  it('should give high-risk operations a separate budget from low-risk operations', async () => {
    const highRiskHandler = () => {};
    Object.defineProperty(highRiskHandler, 'name', { value: 'highRiskHandler' });
    const lowRiskHandler = () => {};
    Object.defineProperty(lowRiskHandler, 'name', { value: 'lowRiskHandler' });

    const highRiskContext = createMockExecutionContext(
      'POST',
      '10.0.0.2',
      highRiskHandler,
      { user: { sub: 'user-hr', role: 'user' } },
    );
    const lowRiskContext = createMockExecutionContext(
      'POST',
      '10.0.0.2',
      lowRiskHandler,
      { user: { sub: 'user-hr', role: 'user' } },
    );

    reflector.get.mockImplementation((key: string, handler: any) => {
      if (handler === highRiskHandler) {
        return { limit: 100, window: 60, risk: 'high' };
      }
      return { limit: 100, window: 60, risk: 'low' };
    });

    // Exhaust the high-risk budget (2 tokens).
    await guard.canActivate(highRiskContext);
    await guard.canActivate(highRiskContext);
    await expect(guard.canActivate(highRiskContext)).rejects.toThrow(HttpException);

    // Low-risk operations for the same user are unaffected.
    expect(await guard.canActivate(lowRiskContext)).toBe(true);
  });

  it('should apply a tighter budget for low-reputation IPs', async () => {
    const reputationGuard = new RateLimitGuard(reflector, configService, store, {
      ipReputation: () => 0.1,
    });

    const context = createMockExecutionContext('GET', '192.0.2.1');
    reflector.get.mockReturnValue(undefined);

    // getLimit * 0.25 = 12 tokens.
    for (let i = 0; i < 12; i++) {
      await reputationGuard.canActivate(context);
    }
    await expect(reputationGuard.canActivate(context)).rejects.toThrow(
      HttpException,
    );
  });

  it('should emit decision records via the onDecision hook', async () => {
    const decisions : any[] = [];
    const observingGuard = new RateLimitGuard(reflector, configService, store, {
      onDecision: (record) => decisions.push(record),
    });

    const context = createMockExecutionContext('GET', '192.0.2.2');
    reflector.get.mockReturnValue(undefined);

    await observingGuard.canActivate(context);
    expect(decisions.length).beGreaterThan(0);
    expect(decisions[0]).toMatchObject({ allowed: true });
  });
});
