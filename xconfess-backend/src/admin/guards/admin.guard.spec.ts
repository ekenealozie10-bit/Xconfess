import { AdminGuard } from '../../auth/admin.guard';
import { ForbiddenException } from '@nestjs/common';
import { UserRole } from '../../user/entities/user.entity';

describe('AdminGuard', () => {
  const buildContext = (user: any) => ({
    switchToHttp: () => ({
      getRequest: () => ({ user }),
    }),
  });

  const expectForbiddenFor = (user: any) => {
    const guard = new AdminGuard();
    expect(() => guard.canActivate(buildContext(user))).toThrow(ForbiddenException);
  };

  it('throws if no user', () => {
    expectForbiddenFor(null);
  });

  it('throws if user is undefined', () => {
    expectForbiddenFor(undefined);
  });

  it('throws if anonymous (no role)', () => {
    expectForbiddenFor( { id: 'anon' });
  });

  it('throws if not admin', () => {
    expectForbiddenFor( { id: 'u', role: UserRole.USER });
  });

  it('throws for moderator', () => {
    expectForbiddenFor({ id: 'm', role: UserRole.MODERATOR });
  });

  it('throws for resource owner with owner metadata', () => {
    expectForbiddenFor({
      id: 'owner-1',
      role: UserRole.USER,
      ownerId: 'owner-1',
    });
  });

  it('throws when object ID is substituted in the request params', () => {
    const guard = new AdminGuard();
    const ctx = {
      switchToHttp: () => ({
        getRequest: () => ({
          user: { id: 'u', role: UserRole.USER },
          params: { id: 'substituted-object-id' },
        }),
      }),
    };
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('allows admin', () => {
    const guard = new AdminGuard();
    expect(guard.canActivate(buildContext({ role: UserRole.ADMIN }))).toBe(true);
  });

  it('allows admin even when object ID is substituted', () => {
    const guard = new AdminGuard();
    const ctx = {
      switchToHttp: () => ({
        getRequest: () => ({
          user: { id: 'admin-1', role: UserRole.ADMIN },
          params: { id: 'substituted-object-id' },
        }),
      }),
    };
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('returns consistent ForbiddenException for all unauthorized roles', () => {
    const guard = new AdminGuard();
    const unauthorized = [null, undefined, { role: UserRole.USER }, { role: UserRole.MODERATOR }];
    for (const user of unauthorized) {
      try {
        guard.canActivate(buildContext(user));
        throw new Error('Expected ForbiddenException');
      } catch (err) {
        expect(err).toBeInstanceOf(ForbiddenException);
        expect((err as ForbiddenException).message).toBeDefined();
      }
    }
  });
});
