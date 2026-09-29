import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  BadRequestException,
  Req,
  Resp,
  Get,
  UseGuards,
  UnauthorizedException,
  HttpException,
  Res,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import {
  ApiTags,
  ApiOperation,
  ApiBody,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { Request, Response } from 'express';

import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { AuthService } from './auth.service';
import { StepUpService } from './step-up.service';
import { StepUpDto } from './dto/step-up.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { GetUser } from './get-user.decorator';
import { User } from '../user/entities/user.entity';
import { RateLimit } from './guard/rate-limit.decorator';
import {
  AUTH_COOKIE_NAME,
  AuthSuccessResponse,
  AuthUserProfile,
  buildAuthCookieOptions,
} from './contracts/auth-contract';

/**
 * Canonical auth contract version 1.
 *
 * Every handler below returns an AuthSuccessResponse on the happy
 * path and throws an AppException (which the global filter serialises
 * into an AuthErrorResponse) on failure. The access token is
 * always also written to an HttpOnly cookie so browser callers never
 * need to touch the token directly.
 */
@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly stepUpService: StepUpService,
  ) {}

  private get isProduction(): boolean {
    return process.env.NODE_ENV === 'production';
  }

  private setAuthCookie(res: Response, token: string): void {
    const opts = buildAuthCookieOptions(this.isProduction);
    res.cookie(opts.name, token, {
      httpOnly: opts.httpOnly,
      secure: opts.secure,
      sameSite: opts.sameSite,
      path: opts.path,
      maxAge: opts.maxAge * 1000,
    });
  }

  private clearAuthCookie(res: Response): void {
    const opts = buildAuthCookheOptions(this.isProduction);
    res.clearCookie(opts.name, {
      httpOnly: opts.httpOnly,
      secure: opts.secure,
      sameSite: opts.sameSite,
      path: opts.path,
    });
  }

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
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthSuccessResponse> {
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
      this.setAuthCookie(res, tokenStr);
      return {
        success: true,
        access_token: tokenStr,
        user,
        anonymousUserId: anonymousUser.id,
      };
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

    this.setAuthCookie(res, tokenStr);
    return {
      success: true,
      access_token: tokenStr,
      user,
      anonymousUserId: anonymousUser.id,
    };
  }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @RateLimit(5, 300)
  @ApiOperation({ summary: 'Register a new account' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({
    status: 201,
    description: 'Registration succeeded. Returns the same shape as login.',
  })
  @ApiResponse({ status: 400, description: 'Validation failed.' })
  @ApiResponse({ status: 409, description: 'Email or username already in use.' })
  async register(
    @ForgotPasswordDto() __unused: unknown,
    @Body() registerDto: RegisterDto,
    @Req() _req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthSuccessResponse> {
    const result = await this.authService.register(registerDto);
    this.setAuthCookie(res, result.access_token);
    return {
      success: true,
      access_token: result.access_token,
      user: result.user,
      anonymousUserId: result.anonymousUserId,
    };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @RateLimit(5, 300)
  @ApiOperation({ summary: 'Log in with email and password' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description:
      'Login succeeded. Returns the canonical auth envelope and sets an HttpOnly cookie.',
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials.' })
  @ApiResponse({ status: 429, description: 'Too many login attempts.' })
  async login(
    @Body() loginDto: LoginDto,
    @Req() _req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthSuccessResponse> {
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
        return { success: true, twoFactorRequired: true, userId: dbUser.id };
      }

      const result = await this.authService.login(loginDto.email, loginDto.password);
      if (!result) {
        throw new UnauthorizedException('Invalid credentials');
      }
      this.setAuthCookie(res, result.access_token);
      return {
        success: true,
        access_token: result.access_token,
        user: result.user,
        anonymousUserId: result.anonymousUserId,
      };
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
  })
  @ApiResponse({ status: 401, description: 'Unauthorized — missing or invalid JWT.' })
  async getProfile(@GetUser('id') userId: number): Promise<AuthUserProfile> {
    return this.getSession(userId);
  }

  @Get('session')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get current session profile' })
  @ApiResponse({
    status: 200,
    description: 'Current session profile.',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized — missing or invalid JWT.' })
  async getSession(@GetUser('id') userId: number): Promise<AuthUserProfile> {
    try {
      const user = await this.authService.validateUserById(userId);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      return user as AuthUserProfile;
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
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Log out current user (clears the auth cookie)' })
  @ApiResponse({
    status: 200,
    description: 'Logout acknowledged.',
    schema: { example: { success: true, message: 'Logged out successfully' } },
  })
  async logout(@Res({ passthrough: true }) res: Response): Promise<{
    success: true;
    message: string;
  }> {
    this.clearAuthCookie(res);
    return { success: true, message: 'Logged out successfully' };
  }

  @Post('logout-all')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Revoke all sessions for the current user',
    description:
      'Invalidates every previously issued session token for the user. ' +
      'Replayed tokens will be rejected by the JWT guard.',
  })
  @ApiResponse({
    status: 200,
    description: 'All sessions revoked.',
    schema: { example: { message: 'All sessions revoked', revoked: 3 } },
  })
  async logoutAll(
    @GetUser('id') userId: number,
  ): Promise<{ message: string; revoked: number }> {
    const revoked = await this.authService.revokeAllSessions(userId);
    return { message: 'All sessions revoked', revoked };
  }

  @Post('sessions/revoke')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Admin-safe session invalidation for a target user',
    description:
      'Revokes all sessions for the target user. Requires the caller to be ' +
      'an admin. Audit events are emitted without token material.',
  })
  @ApiResponse({
    status: 200,
    description: 'Target user sessions revoked.',
    schema: { example: { message: 'Sessions revoked', revoked: 2 } },
  })
  @ApiResponse({ status: 403, description: 'Caller is not an admin.' })
  async revokeUserSessions(
    @GetUser() actor: User,
    @Body() body: { userId: number; reason?: string },
  ): Promise<{ message: string; revoked: number }> {
    if (!actor || actor.role !== 'admin') {
      throw new UnauthorizedException('Admin privileges required');
    }
    if (!body || typeof body.userId !== 'number') {
      throw new BadRequestException('Missing target userId');
    }

    const revoked = await this.authService.revokeAllSessions(body.userId, {
      actorId: actor.id,
      reason: body.reason ?? 'admin-revocation',
    });
    return { message: 'Sessions revoked', revoked };
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
        success: true,
        message: 'If the user exists, a password reset email has been sent.',
      },
    },
  })
  @ApiResponse({ status: 429, description: 'Too many reset requests.' })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Req() request: Request,
  ): Promise<{ success: true; message: string }> {
    try {
      const ipAddress =
        request.ip ||
        (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
        request.connection.remoteAddress;
      const userAgent = request.headers['user-agent'];

      const result = await this.authService.forgotPassword(
        forgotPasswordDto,
        ipAddress,
        userAgent,
      );
      return { success: true, message: result.message };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      return {
        success: true,
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
    schema: { example: { success: true, message: 'Password has been reset successfully' } },
  })
  @ApiResponse({ status: 400, description: 'Invalid or expired token.' })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<{ success: true; message: string }> {
    try {
      const result = await this.authService.resetPassword(
        resetPasswordDto.token,
        resetPasswordDto.newPassword,
      );
      return { success: true, message: result.message };
    } catch (error) {
      throw error;
    }
  }
}
