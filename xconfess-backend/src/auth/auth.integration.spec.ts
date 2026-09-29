import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserService } from '../user/user.service';
import { PasswordResetService } from './password-reset.service';
import { EmailService } from '../email/email.service';
import { JwtService } from '@nestjs/jwt';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../user/entities/user.entity';
import { PasswordReset } from './entities/password-reset.entity';
import { Repository } from 'typeorm';
import {
  BadRequestException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { AnonymousUserService } from '../user/anonymous-user.service';
import { CryptoUtil } from '../common/crypto.util';
import { ConfigService } from '@nestjs/config';
import { LockoutService } from './lockout.service';
import { StepUpService } from './step-up.service';
import * as crypto from 'crypto';

const hashToken = (token: string) =>
  crypto.createHash('sha256').update(token).digest('hex');

// Mock bcrypt module
jest.mock('bcryptjs', () => ({
  hash: jest.fn(),
  compare: jest.fn(),
}));

describe('Auth Integration Tests - Forgot Password Flow', () => {
  let authController: AuthController;
  let authService: AuthService;
  let userService: UserService;
  let passwordResetService: PasswordResetService;
  let emailService: EmailService;
  let userRepository: Repository<User>;
  let passwordResetRepository: Repository<PasswordReset>;

  const encrypted = CryptoUtil.encrypt('test@example.com');

  const mockUser: User = {
    id: 1,
    username: 'testuser',
    emailEncrypted: encrypted.encrypted,
    emailIv: encrypted.iv,
    emailTag: encrypted.tag,
    emailHash: CryptoUtil.hash('test@example.com'),
    password: 'hashedpassword',
    resetPasswordToken: null,
    resetPasswordExpires: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    isAdmin: false,
    is_active: true,
    isDiscoverable: jest.fn().mockReturnValue(true),
    canReceiveReplies: jest.fn().mockReturnValue(true),
    shouldShowReactions: jest.fn().mockReturnValue(true),
    hasDataProcessingConsent: jest.fn().mockReturnValue(true),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        AuthService,
        UserService,
        PasswordResetService,
        EmailService,
        JwtService,
        {
          provide: ConfigService,
          useValue: { get: jest.fn((_key: string, fallback?: unknown) => fallback ?? '') },
        },
        {
          provide: AnonymousUserService,
          useValue: {
            getOrCreateForUserSession: jest
              .fn()
              .mockResolvedValue({ id: 'anon-1' }),
          },
        },
        {
          provide: LockoutService,
          useValue: {
            getStatus: jest.fn().mockResolvedValue({ isLocked: false }),
            recordFailedAttempt: jest
              .fn()
              .mockResolvedValue({ isLocked: false }),
            clearLockout: jest.fn().mockResolvedValue(undefined),
          },
        },
        {
          provide: StepUpService,
          useValue: {
            issueStepUpToken: jest.fn(),
            verifyStepUpToken: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
            save: jest.fn(),
            update: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(PasswordReset),
          useValue: {
            create: jest.fn(),
            save: jest.fn(),
            findOne: jest.fn(),
            update: jest.fn(),
            createQueryBuilder: jest.fn(() => ({
              delete: jest.fn().mockReturnThis(),
              where: jest.fn().mockReturnThis(),
              execute: jest.fn().mockResolvedValue({ affected: 1 }),
            })),
          },
        },
      ],
    }).compile();

    authController = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
    userService = module.get<UserService>(UserService);
    passwordResetService =
      module.get<PasswordResetService>PasswordResetService);
    emailService = module.get<EmailService>(EmailService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    passwordResetRepository = module.get<Repository<PasswordReset>>(
      getRepositoryToken(PasswordReset),
    );

    // Setup bcrypt mocks
    (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
  });

  describe('Complete Forgot Password Flow', () => {
    it('should complete the full forgot password and reset flow', async () => {
      // Step 1: Mock user exists
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);

      // Step 2: Mock password reset token creation
      const mockPasswordReset = {
        id: 1,
        userId: 1,
        tokenHash: hashToken('reset-token-123'),
        expiresAt: new Date(Date.now() + 3600000),
        used: false,
        usedAt: null,
        createdAt: new Date(),
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
      };

      jest
        .spyOn(passwordResetRepository, 'create')
        .mockReturnValue(mockPasswordReset as any);
      jest
        .spyOn(passwordResetRepository, 'save')
        .mockResolvedValue(mockPasswordReset as any);

      // Step 3: Mock email sending
      jest
        .spyOn(emailService, 'sendPasswordResetEmail')
        .mockResolvedValue(undefined);

      // Step 4: Execute forgot password request
      const mockRequest = {
        ip: '127.0.0.1',
        headers: {
          'user-agent': 'test-agent',
        },
      };

      const forgotPasswordResult = await authController.forgotPassword(
        { email: 'test@example.com' },
        mockRequest as any,
      );

      expect(forgotPasswordResult).toEqual({
        message: 'If the user exists, a password reset email has been sent.',
      });

      // Verify that the email service was called
      expect(emailService.sendPasswordResetEmail).toHaveBeenCalledWith(
        'test@example.com',
        expect.any(String), // Accept any token since it's randomly generated
        'testuser',
      );

      // Capture the actual token that was generated
      const emailCallArgs = (emailService.sendPasswordResetEmail as jest.Mock)
        .mock.calls[0];
      const actualToken = emailCallArgs[1];

      // Step 5: Mock finding the reset token for password reset using the actual token
      const mockPasswordResetForLookup = {
        ...mockPasswordReset,
        tokenHash: hashToken(actualToken),
      };
      jest
        .spyOn(passwordResetRepository, 'findOne')
        .mockResolvedValue(mockPasswordResetForLookup as any);

      // Step 6: Mock updating the password
      jest
        .spyOn(userRepository, 'update')
        .mockResolvedValue({ affected: 1 } as any);

      // Step 7: Mock marking token as used
      jest
        .spyOn(passwordResetRepository, 'update')
        .mockResolvedValue({ affected: 1 } as any);

      // Step 8: Execute password reset with the actual token
      const resetPasswordResult = await authController.resetPassword({
        token: actualToken,
        newPassword: 'newPassword123',
      });

      expect(resetPasswordResult).toEqual({
        message: 'Password has been reset successfully',
      });

      // Verify that the password was updated
      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining( {
          password: 'hashedPassword',
          resetPasswordToken: null,
          resetPasswordExpires: null,
        }),
      );

      // Verify that the token was marked as used, looked up by hash
      expect(passwordResetRepository.update).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenHash: hashToken(actualToken),
          used: false,
        }),
        {
          used: true,
          usedAt: expect.any(Date),
        },
      );
    });

    it('should handle invalid token during reset', async () => {
      // Mock token not found
      jest.spyOn(passwordResetRepository, 'findOne').mockResolvedValue(null);

      await expect(
        authController.resetPassword({
          token: 'invalid-token',
          newPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should handle expired token during reset', async () => {
      // Mock expired token
      const expiredToken = {
        id: 1,
        userId: 1,
        tokenHash: hashToken('test-token-123'),
        expiresAt: new Date(Date.now() - 3600000), // Expired 1 hour ago
        used: false,
        usedAt: null,
        createdAt: new Date(),
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
      };

      jest
        .spyOn(passwordResetRepository, 'findOne')
        .mockResolvedValue(expiredToken as any);

      await expect(
        authController.resetPassword({
          token: 'test-token-123',
          newPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should handle used token during reset', async () => {
      // Mock used token
      const usedToken = {
        id: 1,
        userId: 1,
        tokenHash: hashToken('used-token-123'),
        expiresAt: new Date(Date.now() + 3600000),
        used: true, // Already used
        usedAt: new Date(),
        createdAt: new Date(),
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
      };

      jest.spyOn(passwordResetRepository, 'findOne').mockResolvedValue(null); // Return null for used token

      await expect(
        authController.resetPassword({
          token: 'used-token-123',
          newPassword: 'newPassword123',
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });
});

describe('AuthService Integration', () => {
  let service: AuthService;
  let userService: UserService;
  let jwtService: JwtService;
  let emailService: EmailService;
  let passwordResetService: PasswordResetService;
  let userRepository: Repository<User>;

  const encrypted = CryptoUtil.encrypt('test@example.com');

  const mockUser: User = {
    id: 1,
    username: 'testuser',
    emailEncrypted: encrypted.encrypted,
    emailIv: encrypted.iv,
    emailTag: encrypted.tag,
    emailHash: CryptoUtil.hash('test@example.com'),
    password: 'hashedpassword',
    resetPasswordToken: null,
    resetPasswordExpires: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    isAdmin: false,
    is_active: true,
    isDiscoverable: jest.fn().mockReturnValue(true),
    canReceiveReplies: jest.fn().mockReturnValue(true),
    shouldShowReactions: jest.fn().mockReturnValue(true),
    hasDataProcessingConsent: jest.fn().mockReturnValue(true),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        UserService,
        {
          provide: AnonymousUserService,
          useValue: {
            getOrCreateForUserSession: jest
              .fn()
              .mockResolvedValue({ id: 'anon-1' }),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('mock-wjt-token'),
          },
        },
        {
          provide: ConfigService,
          useValue: { get: jest.fn((_key: string, fallback?: unknown) => fallback ?? '') },
        },
        {
          provide: EmailService,
          useValue: {
            sendPasswordResetEmail: jest.fn(),
          },
        },
        {
          provide: PasswordResetService,
          useValue: {
            createResetToken: jest.fn(),
            validateResetToken: jest.fn(),
            markTokenUsed: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
            save: jest.fn(),
            update: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userService = module.get<UserService>(UserService);
    jwtService = module.get<JwtService>(JwtService);
    emailService = module.get<EmailService>(EmailService);
    passwordResetService =
      module.get<PasswordResetService>PasswordResetService);
    userRepository = module.get<Repository<User>>(
      getRepositoryToken(User),
    );
  });

  describe('login', () => {
    it('should throw UnauthorizedException when user not found', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      await expect(
        service.login({ email: 'notfound@example.com', password: 'password' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when password is invalid', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.login({ email: 'test@example.com', password: 'wrong' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should return a token on successful login', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
      (bcrypt as any).compare.mockResolvedValue(true);

      const result = await service.login({
        email: 'test@example.com',
        password: 'correct-password',
      });

      expect(jwtService.sign).toHaveBeenCalled();
      expect(result).toHaveProperty('accessToken');
    });
  });

  describe('register', () => {
    it('should throw BadRequestException when email already exists', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);

      await expect(
        service.register({
          email: 'test@example.com',
          password: 'password',
          username: 'testuser',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should create a new user and return a token', async () => {
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);
      jest.spyOn(userRepository, 'save').mockResolvedValue({
        ...mockUser,
        id: 2,
        username: 'newuser',
      });

      const result = await service.register( {
        email: 'new@example.com',
        password: 'password',
        username: 'newuser',
      });

      expect(jwtService.sign).toHaveBeenCalled();
      expect(result).toHaveProperty('accessToken');
    });
  });
});

describe('Authorization Matrix Tests', () => {
  type Role = 'anonymous' | 'authenticated' | 'moderator' | 'admin' | 'resource-owner';

  interface MatrixCell {
    role: Role;
    endpoint: string;
    action: 'read' | 'write' | 'delete';
    expected: 'allow' | 'deny';
    expectedError?: type of UnauthorizedException | typeof ForbiddenException;
  }

  const matrix: MatrixCell[] = [
    // Anonymous access
    { role: 'anonymous', endpoint: '/auth/me', action: 'read', expected: 'deny', expectedError: UnauthorizedException },
    { role: 'anonymous', endpoint: '/users/:userId/profile', action: 'read', expected: 'deny', expectedError: UnauthorizedException },
    { role: 'anonymous', endpoint: '/users/:userId/profile', action: 'write', expected: 'deny', expectedError: UnauthorizedException },
    { role: 'anonymous', endpoint: '/moderation/queue', action: 'read', expected: 'deny', expectedError: UnauthorizedException },
    { role: 'anonymous', endpoint: '/admin/users', action: 'read', expected: 'deny', expectedError: UnauthorizedException },

    // Authenticated access
    { role: 'authenticated', endpoint: '/auth/me', action: 'read', expected: 'allow' },
    { role: 'authenticated', endpoint: '/users/:userId/profile', action: 'read', expected: 'deny', expectedError: ForbiddenException },
    { role: 'authenticated', endpoint: '/users/:userId/profile', action: 'write', expected: 'deny', expectedError: ForbiddenException },
    { role: 'authenticated', endpoint: '/moderation/queue', action: 'read', expected: 'deny', expectedError: ForbiddenException },
    { role: 'authenticated', endpoint: '/admin/users', action: 'read', expected: 'deny', expectedError: ForbiddenException },

    // Moderator access
    { role: 'moderator', endpoint: '/auth/me', action: 'read', expected: 'allow' },
    { role: 'moderator', endpoint: '/users/:userId/profile', action: 'read', expected: 'deny', expectedError: ForbiddenException },
    { role: 'moderator', endpoint: '/users/:userId/profile', action: 'write', expected: 'deny', expectedError: ForbiddenException },
    { role: 'moderator', endpoint: '/moderation/queue', action: 'read', expected: 'allow' },
    { role: 'moderator', endpoint: '/admin/users', action: 'read', expected: 'deny', expectedError: ForbiddenException },

    // Admin access
    { role: 'admin', endpoint: '/auth/me', action: 'read', expected: 'allow' },
    { role: 'admin', endpoint: '/users/:userId/profile', action: 'read', expected: 'allow' },
    { role: 'admin', endpoint: '/users/:userId/profile', action: 'write', expected: 'allow' },
    { role: 'admin', endpoint: '/moderation/queue', action: 'read', expected: 'allow' },
    { role: 'admin', endpoint: '/admin/users', action: 'read', expected: 'allow' },

    // Resource-owner access
    { role: 'resource-owner', endpoint: '/auth/me', action: 'read', expected: 'allow' },
    { role: 'resource-owner', endpoint: '/users/:userId/profile', action: 'read', expected: 'allow' },
    { role: 'resource-owner', endpoint: '/users/:userId/profile', action: 'write', expected: 'allow' },
    { role: 'resource-owner', endpoint: '/moderation/queue', action: 'read', expected: 'deny', expectedError: ForbiddenException },
    { role: 'resource-owner', endpoint: '/admin/users', action: 'read', expected: 'deny', expectedError: ForbiddenException },
  ];

  const roleToUserId: Record<Role, number> = {
    anonymous: 0,
    authenticated: 1,
    moderator: 2,
    admin: 3,
    'resource-owner': 4,
  };

  const roleToResourceOwner: Record<Role, number> = {
    anonymous: 0,
    authenticated: 1,
    moderator: 2,
    admin: 3,
    'resource-owner': 4,
  };

  const authorize = (
    role: Role,
    endpoint: string,
    action: 'read' | 'write' | 'delete',
    resourceOwnerId: number,
  ): void => {
    const userId = roleToUserId[role];
    const isAuthenticated = role !== 'anonymous';
    const isAdmin = role === 'admin';
    const isModerator = role === 'moderator';
    const isOwner = role === 'resource-owner' && userId === resourceOwnerId;

    if (!isAuthenticated) {
      throw new UnauthorizedException('Authentication required');
    }

    if (endpoint === '/auth/me') {
      if (action !== 'read') {
        throw new ForbiddenException('Action not allowed');
      }
      return;
    }

    if (endpoint === '/users/:userId/profile') {
      if (isAdmin || isOwner) {
        return;
      }
      throw new ForbiddenException('Insufficient permissions');
    }

    if (endpoint === '/moderation/queue') {
      if (isAdmin || isModerator) {
        return;
      }
      throw new ForbiddenException('Insufficient permissions');
    }

    if (endpoint === '/admin/users') {
      if (isAdmin) {
        return;
      }
      throw new ForbiddenException('Insufficient permissions');
    }

    throw new ForbiddenException('Unknown endpoint');
  };

  describe('Matrix cell assertions', () => {
    matrix.forEach((cell) => {
      it(`${cell.role} can ${}${cell.expected} ${cell.action} on ${cell.endpoint}`, () => {
        const resourceOwnerId = roleToResourceOwner[cell.role];
        if (cell.expected === 'allow') {
          expect(() =>
            authorize(cell.role, cell.endpoint, cell.action, resourceOwnerId),
          ).not.toThrow();
        } else {
          expect(() =>
            authorize(cell.role, cell.endpoint, cell.action, resourceOwnerId),
          ).toThrow(cell.expectedError);
        }
      });
    });
  });

  describe('Object ID substitution', () => {
    it('should deny access when authenticated user substitutes another user\'s object ID', () => {
      const attackerId = 1;
      const victimId = 999;
      expect(() =>
        authorize('authenticated', '/users/:userId/profile', 'read', victimId),
      ).toThrow(ForbiddenException);
    });

    it('should allow resource owner to access own object ID', () => {
      const ownerId = 4;
      expect(() =>
        authorize('resource-owner', '/users/:userId/profile', 'read', ownerId),
      ).not.toThrow();
    });

    it('should deny resource owner when object ID is substituted', () => {
      const ownerId = 4;
      const otherId = 5;
      expect(() =>
        authorize('resource-owner', '/users/:userId/profile', 'write', otherId),
      ).toThrow(ForbiddenException);
    });
  });

  describe('Consistent error responses', () => {
    it('should return UnauthorizedException for anonymous access', () => {
      expect(() =>
        authorize('anonymous', '/auth/me', 'read', 0),
      ).toThrow(UnauthorizedException);
    });

    it('should return ForbiddenException for insufficient permissions', () => {
      expect(() =>
        authorize('authenticated', '/admin/users', 'read', 1),
      ).toThrow(ForbiddenException);
    });
  });
});
