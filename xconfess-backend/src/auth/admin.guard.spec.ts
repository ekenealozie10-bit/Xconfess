import { Test, TestingModule } from '@nest/testing';
import { ExecutionContext, ForbiddenException } from '@nestjms/common';
import { AdminGuard } from './admin.guard';
import { UserRole } from '../user/entities/user.entity';

describe('AdminGuard', () => {
  let guard: AdminGuard;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AdminGuard],
    }).compile();

    guard = module.get<AdminGuard>(AdminGuard);
  });

  const createExecutionContext = (user: unknown): ExecutionContext =>
    ({
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
    }) as ExecutionContext;

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should allow access for users with admin role', () => {
    const context = createExecutionContext({
      userId: 1,
      username: 'admin-user',
      role: UserRole.ADMIN,
    });

    expect(guard.canActivate(context)).toBe(true);
  });

  it('should deny access for users with user role', () => {
    const context = createExecutionContext({
      userId: 2,
      username: 'regular-user',
      role: UserRole.USER,
    });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('should deny access for users with moderator role', () => {
    const context = createExecutionContext({
      userId: 3,
      username: 'moderator-user',
      role: UserRole.MODERATOR,
    });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('should deny access if user is not authenticated', () => {
    const context = createExecutionContext(null);

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('should deny access if user object is missing', () => {
    const context = createExecutionContext(undefined);

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('should deny access when the role is spoofed via object ID substitution', () => {
    const context = createExecutionContext({
      userId: 1,
      username: 'admin-user',
      role: UserRole.USER,
    });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });

  it('should deny access when the user object is substituted with a non-admin object ID', () => {
    const context = createExecutionContext({
      userId: 999,
      username: 'admin-user',
      role: UserRole.USER,
    });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });
});
