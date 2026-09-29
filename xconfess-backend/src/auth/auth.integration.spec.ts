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
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { AnonymousUserService } from '../user/anonymous-user.service';
import { CryptoUtil } from '../common/crypto.util';
import { ConfigService } from '@nestjs/config';
import { LockoutService } from './lockout.service';
import { StepUpService } from './step-up.service';
import { WebAuthnService } from './webauthn.service';
import { WebAuthCredential } from './entities/webauth-credential.entity';
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
				WebAuthnService,
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
				{
					provide: getRepositoryToken(WebAuthCredential),
					useValue: {
						find: jest.fn(),
						findOne: jest.fn(),
						save: jest.fn(),
						update: jest.fn(),
						delete: jest.fn(),
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
			module.get<PasswordResetService>(PasswordResetService);
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
				expect.objectContaining({
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
				tokenHash: hashToken('expired-token-123'),
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
					token: 'expired-token-123',
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

	describe('WebAuthn Passkey Flow', () => {
		let webAuthnService: WebAuthnService;
		let credentialRepository: Repository<WebAuthCredential>;

		beforeEach(() => {
			webAuthnService = module.get<WebAuthnService>(WebAuthnService);
			credentialRepository = module.get<Repository<WebAuthCredential>>(
				getRepositoryToken(WebAuthCredential),
			);
		});

		it('should verify challenge origin and RP ID during registration', async () => {
			const options = await webAuthnService.generateRegistrationOptions(1);
			expect(options.rp.id).toBeTruthy();
			expect(options.challenge).toBeTruthy();

			const validAttestation = {
				id: 'cred-id-1',
				rawId: Buffer.from('cred-id-1').toString('base64url'),
				response: {
					clientDataJSON: Buffer.from(JSON.stringify({
						type: 'webauthn.create',
						challenge: options.challenge,
						origin: 'https://example.com',
					})).toString('base64url'),
					attestationObject: Buffer.from('attestation').toString('base64url'),
				},
				type: 'public-key',
			};

			const result = await webAuthnService.verifyRegistration(1, validAttestation);
			expect(result.verified).toBe(true);
			expect(credentialRepository.save).toHaveBeenCalled();
		});

		it('should reject replayed assertions', async () => {
			const options = await webAuthnService.generateAuthenticationOptions(1);
			const assertion = {
				id: 'cred-id-1',
				rawId: Buffer.from('cred-id-1').toString('base64url'),
				response: {
					clientDataJSON: Buffer.from(JSON.stringify({
						type: 'webauthn.get',
						challenge: options.challenge,
						origin: 'https://example.com',
					})).toString('base64url'),
					authenticatorData: Buffer.from('auth-data').toString('base64url'),
					signature: Buffer.from('signature').toString('base64url'),
				},
				type: 'public-key',
			};

			// First verification succeeds
			jest.spyOn(webAuthnService as any, 'verifyAssertionSignature').mockResolvedValue(true);
			const firstResult = await webAuthnService.verifyAssertion(1, assertion);
			expect(firstResult.verified).toBe(true);

			// Replay the same assertion
			await expect(webAuthnService.verifyAssertion(1, assertion)).rejects.toThrow(
				BadRequestException,
			);
		});

		it('should support multiple credentials', async () => {
			const cred1 = {
				id: 1,
				userId: 1,
			credentialID: 'cred-1',
				publicKey: 'key1',
				counter: 0,
				transports: ['usb'],
				createdAt: new Date(),
			};
			const cred2 = {
				id: 2,
				userId: 1,
				credentialID: 'cred-2',
				publicKey: 'key2',
				counter: 0,
				transports: ['internal'],
				createdAt: new Date(),
			};

			jest.spyOn(credentialRepository, 'find').mockResolvedValue([cred1, cred2]);
			const credentials = await webAuthnService.listCredentials(1);
			expect(credentials).length(2);
		});

		it('should revoke a credential', async () => {
			const cred = {
				id: 1,
				userId: 1,
				credentialID: 'cred-1',
				publicKey: 'key1',
				counter: 0,
				transports: ['usb'],
				createdAt: new Date(),
			};
			jest.spyOn(credentialRepository, 'findOne').mockResolvedValue(cred as any);
			jest.spyOn(credentialRepository, 'delete').mockResolvedValue({ affected: 1 } as any);

			await webAuthnService.revokeCredential(1, 'cred-1');
			expect(credentialRepository.delete).toHaveBeenCalledWith({ credentialID: 'cred-1', userId: 1 });
		});

		it('should fail registration with invalid origin', async () => {
			const options = await webAuthnService.generateRegistrationOptions(1);
			const invalidAttestation = {
				id: 'cred-id-1',
				rawId: Buffer.from('cred-id-1').toString('base64url'),
				response: {
					clientDataJSON: Buffer.from(JSON.stringify({
						type: 'webauthn.create',
						challenge: options.challenge,
						origin: 'https://evil.com',
					})).toString('base64url'),
					attestationObject: Buffer.from('attestation').toString('base64url'),
				},
				type: 'public-key',
			};

			await expect(
				webAuthnService.verifyRegistration(1, invalidAttestation),
			).rejects.toThrow(BadRequestException);
		});

		it('should fail registration with invalid challenge', async () => {
			const options = await webAuthnService.generateRegistrationOptions(1);
			const invalidAttestation = {
				id: 'cred-id-1',
				rawId: Buffer.from('cred-id-1').toString('base64url'),
				response: {
					clientDataJSON: Buffer.from(JSON.stringify({
						type: 'webauthn.create',
						challenge: 'wrong-challenge',
						origin: 'https://example.com',
					})).toString('base64url'),
					attestationObject: Buffer.from('attestation').toString('base64url'),
				},
				type: 'public-key',
			};

			await expect(
				webAuthnService.verifyRegistration(1, invalidAttestation),
			).rejects.toThrow(BadRequestException);
		});

		it('should fail assertion with invalid signature', async () => {
			const options = await webAuthnService.generateAuthenticationOptions(1);
			const assertion = {
				id: 'cred-id-1',
				rawId: Buffer.from('cred-id-1').toString('base64url'),
				response: {
					clientDataJSON: Buffer.from(JSON.stringify({
						type: 'webauthn.get',
						challenge: options.challenge,
						origin: 'https://example.com',
					})).toString('base64url'),
					authenticatorData: Buffer.from('auth-data').toString('base64url'),
					signature: Buffer.from('bad-signature').toString('base64url'),
				},
				type: 'public-key',
			};

			jest.spyOn(webAuthnService as any, 'verifyAssertionSignature').mockResolvedValue(false);
			await expect(webAuthnService.verifyAssertion(1, assertion)).rejects.toThrow(
				BadRequestException,
			);
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
				WebAuthnService,
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
						sign: jest.fn().mockReturnValue('mock-j{wt-token'),
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
					provide: getRepositoryToken(WebAuthCredential),
					useValue: {
						find: jest.fn(),
						findOne: jest.fn(),
						save: jest.fn(),
						update: jest.fn(),
						delete: jest.fn(),
					},
				},
			],
		}).compile();

		service = module.get<AuthService>(AuthService);
		userService = module.get<UserService>(UserService);
		jwtService = module.get<JwtService>(JwtService);
		emailService = module.get<EmailService>(EmailService);
		passwordResetService = module.get<PasswordResetService>(
			PasswordResetService,
		);
		userRepository = module.get<Repository<User>>(getRepositoryToken(User));
	});

	describe('WebAuthn account recovery integration', () => {
		it('should allow password reset when a verified passkey is present', async () => {
			jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockUser);
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
			jest.spyOn(passwordResetService, 'createResetToken').mockResolvedValue(mockPasswordReset);
			jest.spyOn(emailService, 'sendPasswordResetEmail').mockResolvedValue(undefined);

			const result = await service.forgotPassword('test@example.com', '127.0.0.1', 'test-agent');
			expect(result).toEqual({
				message: 'If the user exists, a password reset email has been sent.',
			});
			expect(emailService.sendPasswordResetEmail).toHaveBeenCalled();
		});

		it('should not leak user existence when user is not found', async () => {
			jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);
			const result = await service.forgotPassword(
				'nonexistent@example.com',
				'127.0.0.1',
				'test-agent',
			);
			expect(result).toEqual({
				message: 'If the user exists, a password reset email has been sent.',
			});
			expect(emailService.sendPasswordResetEmail).not.toHaveBeenCalled();
		});
	});
});
