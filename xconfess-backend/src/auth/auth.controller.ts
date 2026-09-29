import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  BadRequestException,
  Req,
  Get,
  UseGuards,
  UnauthorizedException,
  HttpException,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import {
  ApiTags,
  ApiOperation,
  ApiBody,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { Request } from 'express';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { AuthService } from './auth.service';
import { StepUpService } from './step-up.service';
import { StepUpDto } from './dto/step-up.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { GetUser } from './get-user.decorator';
import { User } from '../user/entities/user.entity';
import { RateLimit } from './guard/rate-limit.decorator';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly stepUpService: StepUpService,
  ) {}

  @Post('step-up')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @RateLimit(5, 60)
  @ApiBearerAuth()
  @ApiOperation({
    summary:
      'Re-authenticate (password or TOTP) to obtain a short-lived step-up proof',
    description:
      'Returns a step-up token to be sent in the "x-step-up-token" header on ' +
      'destructive admin actions. The proof expires quickly.',
  })
  @ApiResponse({
    status: 200,
    description: 'Step-up proof issued.',
    schema: {
      example: {
        stepUpToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        expiresIn: 300,
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Step-up verification failed.' })
  async stepUp(
    @GetUser('id') userId: number,
    @Body() dto: StepUpDto,
  ): Promise<{ stepUpToken: string; expiresIn: number }> {
    return this.stepUpService.createProof(userId, dto);
  }

  @Post('2fa/setup')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Begin TOTP setup — returns QR code and secret (base32)' })
  async setup2fa(@GetUser('id') userId: number): Promise<any> {
    const secret = speakeasy.generateSecret({ name: `Xconfess (${userId})` });

    const otpauth = secret.otpauth_url as string;
    const qrDataUrl = await QRCode.toDataURL(otpauth);

    return { secret: secret.base32, qr: qrDataUrl };
  }

  @Post('2fa/verify-setup')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Verify initial TOTP code and persist secret' })
  async verifySetup(
    @GetUser('id') userId: number,
    @Body() body: { secret: string; token: string },
  ): Promise<{ success: boolean; recoveryCodes?: string[] }> {
    const { secret, token } = body as any;
    if (!secret || !token) throw new BadRequestException('Missing secret or token');

    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1,
    });

    if (!verified) throw new UnauthorizedException('Invalid TOTP token');

    // encrypt and save secret
    const { CryptoUtil } = require('../common/crypto.util');
    const enc = CryptoUtil.encrypt(secret);
    await (this as any).authService.userService.setTotpSecret(
      userId,
      enc.encrypted,
      enc.iv,
      enc.tag,
    );

    // generate recovery codes
    const codes = Array.from({ length: 10 }, () =>
      Math.random().toString(36).slice(2, 10).toUpperCase(),
    );
    const recEnc = CryptoUtil.encrypt(JSON.stringify(codes));
    await (this as any).authService.userService.setRecoveryCodes(userId, recEnc.encrypted, recEnc.iv, recEnc.tag);

    return { success: true, recoveryCodes: codes };
  }

  @Post('2fa/disable')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Disable TOTP for current user' })
  async disable2fa(@GetUser('id') userId: number): Promise<{ success: boolean }> {
    await (this as any).authService.userService.disableTotp(userId);
    return { success: true };
  }

  @Post('2fa/login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @RateLimit(5, 60)
  @ApiOperation({ summary: 'Verify TOTP token during login (after password).' })
  async login2fa(
    @Body() body: { userId: number; token?: string; recoveryCode?: string },
  ): Promise<{ access_token?: string; user?: any; anonymousUserId?: string }> {
    const { userId, token, recoveryCode } = body as any;
    if (!userId) throw new BadRequestException('Missing userId');

    const user = await (this as any).authService.validateUserById(userId);
    if (!user) throw new UnauthorizedException('Invalid user');

    const svc = (this as any).authService.userService;
    const dbUser = await svc.findById(userId as number);

    const { CryptoUtil } = require('../common/crypto.util');

    if (recoveryCode) {
      const consumed = await svc.consumeRecoveryCode(userId, recoveryCode);
      if (!consumed) throw new UnauthorizedException('Invalid recovery code');
      const payload = {
        email: user.email,
        sub: user.id,
        username: user.username,
        role: user.role,
        scopes: user.role === 'admin' ? [] : [],
      };

      const tokenStr = (this as any).authService.jwtService.sign(payload);
      const anonymousUser = await (this as any).authService.anonymousUserService.getOrCreateForUserSession(user.id);
      return { access_token: tokenStr, user, anonymousUserId: anonymousUser.id };
    }

    if (!token) throw new BadRequestException('Missing token');

    if (!dbUser?.totpSecretEncrypted || !dbUser.totpSecretIv || !dbUser.totpSecretTag) {
      throw new UnauthorizedException('TOTP not configured');
    }

    let secretPlain = '';
    try {
      secretPlain = CryptoUtil.decrypt(dbUser.totpSecretEncrypted, dbUser.totpSecretIv, dbUser.totpSecretTag);
    } catch (e) {
      throw new UnauthorizedException('Failed to decrypt TOTP secret');
    }

    const verified = speakeasy.totp.verify({ secret: secretPlain, encoding: 'base32', token, window: 1 });
    if (!verified) throw new UnauthorizedException('Invalid TOTP token');

    const payload = {
      email: user.email,
      sub: user.id,
      username: user.username,
      role: user.role,
      scopes: user.role === 'admin' ? [] : [],
    };

    const tokenStr = (this as any).authService.jwtService.sign(payload);
    const anonymousUser = await (this as any).authService.anonymousUserService.getOrCreateForUserSession(user.id);

    return { access_token: tokenStr, user, anonymousUserId: anonymousUser.id };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @RateLimit(5, 300)
  @ApiOperation({ summary: 'Log in with email and password' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'Login successful. Returns a JWT access token.',
    schema: {
      example: {
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        anonymousUserId: 'anon_7f3a2b1c',
        user: {
          id: 1,
          username: 'alice_42',
          role: 'user',
          is_active: true,
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials.' })
  @ApiResponse({ status: 429, description: 'Too many login attempts.' })
  async login(
    @Body() loginDto: LoginDto,
  ): Promise<any> {
    try {
      const validated = await this.authService.validateUser(
        loginDto.email,
        loginDto.password,
      );

      if (!validated) {
        throw new UnauthorizedException('Invalid credentials');
      }

      const dbUser = await (this as any).authService.userService.findByEmail(loginDto.email);
      if (dbUser && dbUser.totpEnabled) {
        return { twoFactorRequired: true, userId: dbUser.id };
      }

      const result = await this.authService.login(loginDto.email, loginDto.password);
      if (!result) {
        throw new UnauthorizedException('Invalid credentials');
      }
      return result;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new BadRequestException('Login failed: ' + errorMessage);
    }
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current authenticated user profile' })
  @ApiResponse({
    status: 200,
    description: 'Authenticated user profile.',
    schema: {
      example: {
        id: 1,
        username: 'alice_42',
        role: 'user',
        is_active: true,
        email: 'alice@example.com',
        notificationPreferences: {},
        privacy: {
          isDiscoverable: true,
          canReceiveReplies: true,
          showReactions: true,
          dataProcessingConsent: true,
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized — missing or invalid JWT.' })
  async getProfile(@GetUser('id') userId: number): Promise<any> {
    return this.getSession(userId);
  }

  @Get('session')
  @UseGuards(JwtAuthGuard)
  async getSession(@GetUser('id') userId: number): Promise<any> {
    try {
      const user = await this.authService.validateUserById(userId);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      return user;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      throw new BadRequestException('Failed to get session: ' + errorMessage);
    }
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Log out current user (client-side token discard)' })
  @ApiResponse({
    status: 200,
    description: 'Logout acknowledged.',
    schema: { example: { message: 'Logged out successfully' } },
  })
  async logout(): Promise<{ message: string }> {
    return { message: 'Logged out successfully' };
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @RateLimit(3, 300)
  @ApiOperation({ summary: 'Request a password-reset e-mail' })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Password-reset e-mail sent if the account exists.',
    schema: {
      example: {
        message: 'If the user exists, a password reset email has been sent.',
      },
    },
  })
  @ApiResponse({ status: 429, description: 'Too many reset requests.' })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Req() request: Request,
  ): Promise<{ message: string }> {
    try {
      const ipAddress =
        request.ip ||
        (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
        request.connection.remoteAddress;
      const userAgent = request.headers['user-agent'];

      return await this.authService.forgotPassword(
        forgotPasswordDto,
        ipAddress,
        userAgent,
      );
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      return {
        message: 'If the user exists, a password reset email has been sent.',
      };
    }
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password using a token from the reset e-mail' })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully.',
    schema: { example: { message: 'Password has been reset successfully.' } },
  })
  @ApiResponse({ status: 400, description: 'Invalid or expired token.' })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    try {
      return await this.authService.resetPassword(
        resetPasswordDto.token,
        resetPasswordDto.newPassword,
      );
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      throw new BadRequestException('Failed to reset password: ' + errorMessage);
    }
  }

  /**
   * Email change with verification and rollback.
   *
   * Flow:
   *  1. POST /auth/email/change-request with the new address.
   *     - The new address is NOT activated yet.
   *     - A challenge is issued and a verification e-mail is sent to the new address.
   *     - A notification is sent to the old address (recovery window).
   *     - The response is generic and does not reveal account existence.
   *  2. POST /auth/email/change-confirm with the challenge token.
   *     - Validates the challenge, invalidates it (single-use), and activates the new address.
   *     - Replayed or expired challenges fail.
   *  3. POST /auth/email/change-rollback within the recovery window.
   *     - Restores the previous address and invalidates any pending challenge.
   */
  @Post('email/change-request')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @RateLimit(5, 60)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Request an email change (requires verification of the new address)',
    description:
      'Issues a single-use challenge and sends a verification e-mail to the new ' +
      'address. The old address remains active until confirmation and is notified ' +
      'to allow rollback. The response is generic and does not reveal account ' +
      'existence.',
  })
  @ApiResponse({
    status: 200,
    description:
      'If the account exists, a verification e-mail has been sent to the new address.',
    schema: {
      example: {
        message:
          'If the account exists, a verification email has been sent to the new address.',
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized — missing or invalid JWT.' })
  @ApiResponse({ status: 429, description: 'Too many email change requests.' })
  async requestEmailChange(
    @GetUser('id') userId: number,
    @Body() body: { newEmail?: string; password?: string },
    @Req() request: Request,
  ): Promise<{ message: string }> {
    const newEmail = body?.newEmail?.trim();
    if (!newEmail) {
      throw new BadRequestException('Missing newEmail');
    }

    const ipAddress =
      request.ip ||
      (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      request.connection.remoteAddress;
    const userAgent = request.headers['user-agent'];

    try {
      return await this.authService.requestEmailChange(
        userId,
        newEmail,
        body?.password,
        ipAddress,
        userAgent,
      );
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      // Do not leak account existence or internal failures.
      return {
        message:
          'If the account exists, a verification email has been sent to the new address.',
      };
    }
  }

  @Post('email/change-confirm')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @RateLimit(10, 60)
  @ApiOperation({
    summary: 'Confirm an email change using the challenge token',
    description:
      'Activates the new address and invalidates the challenge. Replayed or ' +
      'expired challenges fail.',
  })
  @ApiResponse({
    status: 200,
    description: 'Email address updated.',
    schema: { example: { message: 'Email address updated.' } },
  })
  @ApiResponse({ status: 400, description: 'Invalid, expired, or replayed challenge.' })
  async confirmEmailChange(
    @Body() body: { token?: string },
  ): Promise<{ message: string }> {
    const token = body?.token;
    if (!token) {
      throw new BadRequestException('Missing token');
    }

    try {
      return await this.authService.confirmEmailChange(token);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      throw new BadRequestException('Failed to confirm email change: ' + errorMessage);
    }
  }

  @Post('email/change-rollback')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @RateLimit(5, 60)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Roll back a recent email change to the previous address',
    description:
      'Restores the previous address within the recovery window and invalidates ' +
      'any pending challenge.',
  })
  @ApiResponse({
    status: 200,
    description: 'Email address rolled back.',
    schema: { example: { message: 'Email address rolled back.' } },
  })
  @ApiResponse({ status: 400, description: 'Rollback window expired or not available.' })
  @ApiResponse({ status: 401, description: 'Unauthorized — missing or invalid JWT.' })
  async rollbackEmailChange(
    @GetUser('id') userId: number,
  ): Promise<{ message: string }> {
    try {
      return await this.authService.rollbackEmailChange(userId);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      throw new BadRequestException('Failed to roll back email change: ' + errorMessage);
    }
  }
}
