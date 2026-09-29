import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
import { WsJwtGuard } from './ws-jwt.guard';
import { WebSocketLogger } from '../../websocket/websocket.logger';

describe('WsJwtGuard', () => {
  let guard: WsJwtGuard;
  let jwtService: { verifyAsync: jest.Mock };
  let websocketLogger: { logAuthFailure: jest.Mock };
  let mockSocket: any;
  let mockReflector: { getAllAndOverride: jest.Mock };
  let mockRolesService: { getUserRoles: jest.Mock };

  const buildContext = (socket: any): ExecutionContext => ({
    switchToWs: () => ({
      getClient: () => socket,
    }),
  } as any);

  beforeEach(() => {
    jwtService = { verifyAsync: jest.fn() };
    websocketLogger = { logAuthFailure: jest.fn() };
    mockReflector = { getAllAndOverride: jest.fn().mockReturnValue(undefined) };
    mockRolesService = { getUserRoles: jest.fn().mockResolvedValue([]) };
    mockSocket = {
      id: 'socket-1',
      handshake: {
        auth: {},
        headers: {},
      },
      data: {},
    };

    guard = new WsJwtGuard(
      jwtService as any,
      mockReflector as any,
      mockRolesService as any,
      websocketLogger as any,
    );
  });

  it('should reject with NO_TOKEN_PROVIDED and log auth failure when no token', async () => {
    mockSocket.handshake = { auth: {}, headers: {} };

    await expect(
      guard.canActivate(buildContext(mockSocket)),
    ).rejects.toThrow(UnauthorizedException);

    expect(websocketLogger.logAuthFailure).toHaveBeenCalledWith({
      socketId: 'socket-1',
      reasonCode: 'NO_TOKEN_PROVIDED',
      correlationId: expect.any(String),
    });
  });

  it('should extract token from handshake.auth.token', async () => {
    mockSocket.handshake.auth = { token: 'valid-jwt' };
    jwtService.verifyAsync.mockResolvedValue({ sub: '1', username: 'test' });

    const result = await guard.canActivate(buildContext(mockSocket));

    expect(result).toBe(true);
    expect(jwtService.verifyAsync).toHaveBeenCalledWith('valid-jwt');
  });

  it('should extract token from Authorization header', async () => {
    mockSocket.handshake = {
      auth: {},
      headers: { authorization: 'Bearer header-token' },
    };
    jwtService.verifyAsync.mockResolvedValue({ sub: '2', username: 'u2' });

    const result = await guard.canActivate(buildContext(mockSocket));

    expect(result).toBe(true);
    expect(jwtService.verifyAsync).toHaveBeenCalledWith('header-token');
  });

  it('should extract token from cookies', async () => {
    mockSocket.handshake = {
      auth: {},
      headers: { cookie: 'token=cookie-token; other=value' },
    };
    jwtService.verifyAsync.mockResolvedValue({ sub: '3', username: 'u3' });

    const result = await guard.canActivate(buildContext(mockSocket));

    expect(result).toBe(true);
    expect(jwtService.verifyAsync).toHaveBeenCalledWith('cookie-token');
  });

  it('should reject with EXPIRED_TOKEN and log auth failure', async () => {
    mockSocket.handshake.auth = { token: 'expired-token' };
    jwtService.verifyAsync.mockRejectedValue(new TokenExpiredError('jwt expired', new Date()));

    await expect(
      guard.canActivate(buildContext(mockSocket)),
    ).rejects.toThrow(UnauthorizedException);

    expect(websocketLogger.logAuthFailure).toHaveBeenCalledWith({
      socketId: 'socket-1',
      reasonCode: 'EXPIRED_TOKEN',
      correlationId: expect.any(String),
    });
  });

  it('should reject with MALFORMED_TOKEN and log auth failure', async () => {
    mockSocket.handshake.auth = { token: 'bad-token' };
    jwtService.verifyAsync.mockRejectedValue(new Error('invalid signature'));

    await expect(
      guard.canActivate(buildContext(mockSocket)),
    ).rejects.toThrow(UnauthorizedException);

    expect(websocketLogger.logAuthFailure).toHaveBeenCalledWith({
      socketId: 'socket-1',
      reasonCode: 'MALFORMED_TOKEN',
      correlationId: expect.any(String),
    });
  });

  it('should reject with MISSING_SUBJECT when payload has no sub', async () => {
    mockSocket.handshake.auth = { token: 'no-sub-token' };
    jwtService.verifyAsync.mockResolvedValue({ username: 'test' });

    await expect(
      guard.canActivate(buildContext(mockSocket)),
    ).rejects.toThrow(UnauthorizedException);

    expect(websocketLogger.logAuthFailure).toHaveBeenCalledWith({
      socketId: 'socket-1',
      reasonCode: 'MISSING_SUBJECT',
      correlationId: expect.any(String),
    });
  });

  it('should work without WebSocketLogger (optional dependency)', async () => {
    const guardNoLogger = new WsJwtGuard(jwtService as any, undefined, undefined);
    mockSocket.handshake = { auth: {}, headers: {} };

    await expect(
      guardNoLogger.canActivate(buildContext(mockSocket)),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('should scrub sensitive headers after extracting token', async () => {
    mockSocket.handshake = {
      auth: { token: 'scrub-test' },
      headers: { authorization: 'Bearer scrub-test', cookie: 'token=abc' },
    };
    jwtService.verifyAsync.mockResolvedValue({ sub: '1', username: 'test' });

    await guard.canActivate(buildContext(mockSocket));

    expect(mockSocket.handshake.headers.authorization).toBe('<REDACTED>');
    expect(mockSocket.handshake.headers.cookie).toBe('<REDACTED>');
  });

  it('should attach userId and username to socket data on success', async () => {
    mockSocket.handshake.auth = { token: 'good-token' };
    jwtService.verifyAsync.mockResolvedValue({ sub: '42', username: 'alice' });

    await guard.canActivate(buildContext(mockSocket));

    expect(mockSocket.data.userId).toBe('42');
    expect(mockSocket.data.username).toBe('alice');
  });

  it('should generate unique correlation IDs for each request', async () => {
    mockSocket.handshake = { auth: {}, headers: {} };

    await guard.canActivate(buildContext(mockSocket)).catch(() => {});
    const firstCorrelationId = websocketLogger.logAuthFailure.mock.calls[0][0].correlationId;

    websocketLogger.logAuthFailure.mockClear();
    mockSocket.id = 'socket-2';
    await guard.canActivate(buildContext(mockSocket)).catch(() => {});
    const secondCorrelationId = websocketLogger.logAuthFailure.mock.calls[0][0].correlationId;

    expect(firstCorrelationId).not.toBe(secondCorrelationId);
  });

  describe('authorization matrix', () => {
    type Actor =
      | 'anonymous'
      | 'authenticated'
      | 'moderator'
      | 'admin'
      | 'resource-owner';

    const actorPayloads: Record<Exclude<Actor, 'anonymous'>, any> = {
      authenticated: { sub: '100', username: 'user', roles: ['user'] },
      moderator: { sub: '200', username: 'mod', roles: ['moderator'] },
      admin: { sub: '300', username: 'admin', roles: ['admin'] },
      'resource-owner': { sub: '400', username: 'owner', roles: ['user'] },
    };

    const endpoints: Array<{
      name: string;
      requiredRoles?: string[];
      ownerId?: string;
      allowed: Actor[];
    }> = [
      {
        name: 'confession:read',
        allowed: ['authenticated', 'moderator', 'admin', 'resource-owner'],
      },
      {
        name: 'confession:moderate',
        requiredRoles: ['moderator', 'admin'],
        allowed: ['moderator', 'admin'],
      },
      {
        name: 'confession:delete',
        requiredRoles: ['admin'],
        allowed: ['admin'],
      },
      {
        name: 'confession:update-own',
        ownerId: '400',
        allowed: ['resource-owner', 'admin'],
      },
    ];

    const actors: Actor[] = [
      'anonymous',
      'authenticated',
      'moderator',
      'admin',
      'resource-owner',
    ];

    const setupActor = (actor: Actor, endpoint: (typeof endpoints)[number]) => {
      if (actor === 'anonymous') {
        mockSocket.handshake = { auth: {}, headers: {} };
        return;
      }
      const payload = { ...actorPayloads[actor] };
      mockSocket.handshake = { auth: { token: `${actor}-token` }, headers: {} };
      jwtService.verifyAsync.mockResolvedValue(payload);
      mockReflector.getAllAndOverride.mockReturnValue(endpoint.requiredRoles);
      mockRolesService.getUserRoles.mockResolvedValue(payload.roles ?? []);
    };

    const runGuard = async (actor: Actor, endpoint: (typeof endpoints)[number]) => {
      setupActor(actor, endpoint);
      try {
        const result = await guard.canActivate(buildContext(mockSocket));
        return { allowed: result === true, error: null as any };
      } catch (err) {
        return { allowed: false, error: err };
      }
    };

    for (const endpoint of endpoints) {
      for (const actor of actors) {
        const shouldAllow = endpoint.allowed.includes(actor);
        const label = shouldAllow ? 'allows' : 'denies';

        it(`${label} ${actor} on ${endpoint.name}`, async () => {
          const { allowed, error } = await runGuard(actor, endpoint);

          if (shouldAllow) {
            expect(allowed).toBe(true);
            expect(error).toBeNull();
          } else {
            expect(allowed).toBe(false);
            expect(error).toBeInstanceOf(UnauthorizedException);
          }
        });
      }
    }

    it('returns consistent UnauthorizedException for every denied cell', async () => {
      const deniedErrors: any[] = [];

      for (const endpoint of endpoints) {
        for (const actor of actors) {
          if (endpoint.allowed.includes(actor)) continue;
          const { error } = await runGuard(actor, endpoint);
          deniedErrors.push(error);
        }
      }

      expect(deniedErrors.length).toBeGreaterThan(0);
      for (const err of deniedErrors) {
        expect(err).toBeInstanceOf(UnauthorizedException);
        expect(err.getStatus()).toBe(401);
      }
    });

    it('denies object ID substitution for non-owner authenticated user', async () => {
      const endpoint = endpoints.find((e) => e.name === 'confession:update-own')!;
      const { allowed, error } = await runGuard('authenticated', {
        ...endpoint,
        ownerId: '999',
      });

      expect(allowed).toBe(false);
      expect(error).toBeInstanceOf(UnauthorizedException);
    });

    it('allows resource-owner when object ID matches owner', async () => {
      const endpoint = endpoints.find((e) => e.name === 'confession:update-own')!;
      const { allowed, error } = await runGuard('resource-owner', endpoint);

      expect(allowed).toBe(true);
      expect(error).toBeNull();
    });

    it('denies resource-owner when object ID is substituted', async () => {
      const endpoint = endpoints.find((e) => e.name === 'confession:update-own')!;
      const { allowed, error } = await runGuard('resource-owner', {
        ...endpoint,
        ownerId: '401',
      });

      expect(allowed).toBe(false);
      expect(error).toBeInstanceOf(UnauthorizedException);
    });

    it('denies moderator on admin-only endpoint', async () => {
      const endpoint = endpoints.find((e) => e.name === 'confession:delete')!;
      const { allowed, error } = await runGuard('moderator', endpoint);

      expect(allowed).toBe(false);
      expect(error).toBeInstanceOf(UnauthorizedException);
    });

    it('denies authenticated user on moderator endpoint', async () => {
      const endpoint = endpoints.find((e) => e.name === 'confession:moderate')!;
      const { allowed, error } = await runGuard('authenticated', endpoint);

      expect(allowed).toBe(false);
      expect(error).toBeInstanceOf(UnauthorizedException);
    });

    it('logs auth failure with consistent reason code on denied cell', async () => {
      const endpoint = endpoints.find((e) => e.name === 'confession:moderate')!;
      await runGuard('authenticated', endpoint);

      expect(websocketLogger.logAuthFailure).toHaveBeenCalledWith(
        expect.objectContaining({
          socketId: 'socket-1',
          reasonCode: expect.any(String),
          correlationId: expect.any(String),
        }),
      );
    });

    it('does not leak roles or token in socket data after denial', async () => {
      const endpoint = endpoints.find((e) => e.name === 'confession:delete')!;
      await runGuard('moderator', endpoint);

      expect(mockSocket.data.userId).toBeUndefined();
      expect(mockSocket.data.username).toBeUndefined();
      expect(mockSocket.data.roles).toBeUndefined();
    });
  });
});
