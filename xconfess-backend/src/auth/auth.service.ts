import { maskUserId } from '../utils/mask-user-id';
import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  GoneException,
  UnprocessableEntityException,
  Logger,
  Optional,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { EmailService } from '../email/email.service';
import { PasswordResetService } from './password-reset.service';
import { AnonymousUserService } from '../user/anonymous-user.service';
import { LockoutService } from './lockout.service';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { UserResponse } from '../user/dto/user-response.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { CryptoUtil } from '../common/crypto.util';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { UserRole } from '../user/entities/user.entity';
import { AppException } from '../common/errors/app-exception';
import { ErrorCode } from '../common/errors/error-codes';
import { HttpStatus } from '@nestjs/common';
import { getDefaultAdminStellarInvocationScopes } from '../stellar/stellar-invocation-policy';
import { AnalyticsEventService } from '../analytics/analytics-event.service';

export interface MergeConflict {
  type:
    | 'username'
    | 'message'
    | 'draft'
    | 'tip'
    | 'anchor';
  sourceId: string;
  targetId: string;
  details: Record<string, unknown>;
}

export interface MergeResolution {
  conflictId: string;
  resolution: 'use_source' | 'use_target' | 'merge' | 'skip';
}

export interface MergePreviewResult {
  sourceAnonymousUserId: string;
  targetUserId: number;
  conflicts: MergeConflict[];
  autoResolvable: boolean;
}

export interface MergeResult {
  success: boolean;
  targetUserId: number;
  sourceAnonymousUserId: string;
  transferred: Record<string, number>;
  conflicts: MergeConflict[];
  auditId: string;
  rolledBack: boolean;
}

export interface MergeAuditEntry {
  id: string;
  timestamp: string;
  actorUserId: number;
  sourceAnonymousUserId: string;
  targetUserId: number;
  outcome: 'success' | 'failure' | 'rollback';
  details: Record<string, unknown>;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly mergeAuditLog: MergeAuditEntry[] = [];

  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private passwordResetService: PasswordResetService,
    private anonymousUserService: AnonymousUserService,
    private lockoutService: LockoutService,
    @Optional()
    private readonly analyticsEventService?: AnalyticsEventService,
  ) {}

  async validateUser(
    email: string,
    password: string,
  ): Promise<UserResponse | null> {
    const user = await this.userService.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      if (!user.is_active) {
        throw new AppException(
          'Account is deactivated. Please reactivate your account to continue.',
          ErrorCode.AUTH_ACCOUNT_DEVACTIVATED,
          HttpStatus.UNAUTHORIZED,
        );
      }
      const decryptedEmail = CryptoUtil.decrypt(
        user.emailEncrypted,
        user.emailIv,
        user.emailTag,
      );
      // resetPasswordToken and resetPasswordExpires are internal — never sent to clients.
      return {
        id: user.id,
        username: user.username,
        role: user.role,
        is_active: user.is_active,
        email: decryptedEmail,
        notificationPreferences: user.notificationPreferences || {},
        privacy: {
          isDiscoverable: user.isDiscoverable(),
          canReceiveReplies: user.canReceiveReplies(),
          showReactions: user.shouldShowReactions(),
          dataProcessingConsent: user.hasDataProcessingConsent(),
        },
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      };
    }
    return null;
  }

  async login(
    email: string,
    password: string,
  ): Promise<{
    access_token: string;
    user: UserResponse;
    anonymousUserId: string;
  }> {
    // Check lockout before validating credentials
    const lockStatus = await this.lockoutService.getStatus(email);
    if (lockStatus.isLocked) {
      throw new AppException(
        'Too many failed login attempts. Please try again later.',
        ErrorCode.AUTH_INVALID_CREDENTIALS,
        HttpStatus.UNAUTHORIZED,
      );
    }

    const user = await this.validateUser(email, password);
    if (!user) {
      await this.lockoutService.recordFailedAttempt(email);
      throw new AppException(
        'Invalid credentials',
        ErrorCode.AUTH_INVALID_CREDENTIALS,
        HttpStatus.UNAUTHORIZED,
      );
    }
    await this.lockoutService.clearLockout(email);
    const anonymousUser =
      await this.anonymousUserService.getOrCreateForUserSession(user.id);
    const role = user.role || UserRole.USER;
    const scopes =
      role === UserRole.ADMIN ? getDefaultAdminStellarInvocationScopes() : [];
    const payload: JwtPayload = {
      email: user.email,
      sub: user.id,
      username: user.username,
      role,
      scopes,
    };
    this.analyticsEventService
      ?.record({
        eventName: 'user_login',
        actorId: `user:${user.id}`,
        metadata: { source: 'auth_service' },
      })
      .catch((err) =>
        this.logger.warn(
          `Failed to record login analytics: ${
            err instanceof Error ? err.message : String(err)
          }`,
        ),
      );
    return {
      access_token: this.jwtService.sign(payload),
      user,
      anonymousUserId: anonymousUser.id,
    };
  }

  async generateResetPasswordToken(email: string): Promise<string> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new AppException(
        'Email not found',
        ErrorCode.NOT_FOUND,
        HttpStatus.NOT_FOUND,
      );
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);

    // Token stored internally — never returned to caller or serialized to HTTP response.
    await this.userService.setResetPasswordToken(user.id, token, expiresAt);
    return token;
  }

  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    try {
      const { reset, reason } =
        await this.passwordResetService.consumeValidToken(token);

      if (!reset) {
        this.logger.warn(`Reset token rejected`, { token, reason });

        switch (reason) {
          case 'invalid':
            throw new AppException(
              'Invalid reset token',
              ErrorCode.AUTH_TOKEN_INVALID,
              HttpStatus.BAD_REQUEST,
            );
          case 'expired':
            throw new AppException(
              'Reset token expired',
              ErrorCode.AUTH_SESSION_EXPIRED,
              HttpStatus.UNPROCESSABLE_ENTITY,
            );
          case 'reused':
            throw new AppException(
              'Reset token already used',
              ErrorCode.RESOURCE_GONE,
              HttpStatus.GONE,
            );
          default:
            throw new AppException(
              'Invalid reset token',
              ErrorCode.AUTH_TOKEN_INVALID,
              HttpStatus.BAD_REQUEST,
            );
        }
      }

      await this.userService.updatePassword(reset.userId, newPassword);

      this.logger.log(`Password reset successful`, {
        maskedUserId: maskUserId(reset.userId),
        tokenId: reset.id,
      });

      return { message: 'Password has been reset successfully' };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';

      if (
        error instanceof AppException ||
        error instanceof BadRequestException ||
        error instanceof GoneException ||
        error instanceof UnprocessableEntityException
      ) {
        throw error;
      }

      this.logger.error(`Password reset failed: ${errorMessage}`, {
        token,
        error: errorMessage,
      });
      throw new AppException(
        'Failed to reset password',
        ErrorCode.INTERNAL_SERVER_ERROR,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async validateUserById(userId: number): Promise<UserResponse | null> {
    const user = await this.userService.findById(userId);
    if (user && user.is_active) {
      const decryptedEmail = CryptoUtil.decrypt(
        user.emailEncrypted,
        user.emailIv,
        user.emailTag,
      );
      // resetPasswordToken and resetPasswordExpires are internal — never sent to clients.
      return {
        id: user.id,
        username: user.username,
        role: user.role,
        is_active: user.is_active,
        email: decryptedEmail,
        notificationPreferences: user.notificationPreferences || {},
        privacy: {
          isDiscoverable: user.isDiscoverable(),
          canReceiveReplies: user.canReceiveReplies(),
          showReactions: user.shouldShowReactions(),
          dataProcessingConsent: user.hasDataProcessingConsent(),
        },
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      };
    }
    return null;
  }

  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    try {
      if (!ForgotPasswordDto.validate(forgotPasswordDto)) {
        throw new AppException(
          'Either email or userId must be provided',
          ErrorCode.BAD_REQUEST,
          HttpStatus.BAD_REQUEST,
        );
      }

      let user;

      if (forgotPasswordDto.email) {
        user = await this.userService.findByEmail(forgotPasswordDto.email);
        this.logger.log(`Password reset requested for email: [PROTECTED]`, {
          email: '[PROTECTED]',
          ipAddress,
        });
      } else if (forgotPasswordDto.userId) {
        user = await this.userService.findById(forgotPasswordDto.userId);
        this.logger.log(
          `Password reset requested for masked user ID: ${maskUserId(forgotPasswordDto.userId)}`,
          { maskedUserId: maskUserId(forgotPasswordDto.userId), ipAddress },
        );
      }

      if (!user) {
        this.logger.warn(`Password reset attempted for non-existent user`, {
          maskedUserId: forgotPasswordDto.userId
            ? maskUserId(forgotPasswordDto.userId)
            : undefined,
          ipAddress,
        });
        return {
          message: 'If the user exists, a password reset email has been sent.',
        };
      }

      await this.passwordResetService.invalidateUserTokens(user.id);

      const token = await this.passwordResetService.createResetToken(
        user.id,
        ipAddress,
        userAgent,
      );

      await this.emailService.sendPasswordResetEmail(
        CryptoUtil.decrypt(user.emailEncrypted, user.emailIv, user.emailTag),
        token,
        user.username,
      );

      this.logger.log(`Password reset email sent successfully`, {
        maskedUserId: maskUserId(user.id),
        ipAddress,
        userAgent,
      });

      return {
        message: 'If the user exists, a password reset email has been sent.',
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';

      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error(`Forgot password process failed: ${errorMessage}`, {
        maskedUserId: forgotPasswordDto.userId
          ? maskUserId(forgotPasswordDto.userId)
          : undefined,
        ipAddress,
        error: errorMessage,
      });

      return {
        message: 'If the user exists, a password reset email has been sent.',
      };
    }
  }

  /**
   * Previews a merge between an anonymous identity and an authenticated account.
   * Surfaces conflicts without mutating any data.
   */
  async previewMerge(
    actorUserId: number,
    sourceAnonymousUserId: string,
  ): Promise<MergePreviewResult> {
    const targetUser = await this.userService.findById(actorUserId);
    if (!targetUser || !targetUser.is_active) {
      throw new AppException(
        'Authenticated account not found or inactive',
        ErrorCode.AUTH_UNAUTHORIZED,
        HttpStatus.UNAUTHORIZED,
      );
    }

    const sourceAnonymousUser =
      await this.anonymousUserService.findById(sourceAnonymousUserId);
    if (!sourceAnonymousUser) {
      throw new AppException(
        'Anonymous identity not found',
        ErrorCode.NOT_FOUND,
        HttpStatus.NOT_FOUND,
      );
    }

    if (sourceAnonymousUser.ownerUserId === actorUserId) {
      throw new AppException(
        'Anonymous identity is already owned by this account',
        ErrorCode.BAD_REQUEST,
        HttpStatus.BAD_REQUEST,
      );
    }

    if (
      sourceAnonymousUser.ownerUserId !== null &&
      sourceAnonymousUser.ownerUserId !== actorUserId
    ) {
      throw new AppException(
        'Anonymous identity is owned by another account',
        ErrorCode.AUTH_FORBIDDEN,
        HttpStatus.FORBIDDEN,
      );
    }

    const conflicts = await this.detectMergeConflicts(
      sourceAnonymousUserId,
      actorUserId,
    );

    return {
      sourceAnonymousUserId,
      targetUserId: actorUserId,
      conflicts,
      autoResolvable: conflicts.length === 0,
    };
  }

  /**
   * Atomically transfers ownership of an anonymous identity to an authenticated account.
   * Requires explicit confirmation and resolution for all conflicts.
   */
  async mergeAnonymousIdentity(
    actorUserId: number,
    sourceAnonymousUserId: string,
    confirmation: { confirmed: boolean; resolutions?: MergeResolution[] },
  ): Promise<MergeResult> {
    const auditId = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    if (!confirmation || confirmation.confirmed !== true) {
      this.recordAudit({
        id: auditId,
        timestamp,
        actorUserId,
        sourceAnonymousUserId,
        targetUserId: actorUserId,
        outcome: 'failure',
        details: { reason: 'confirmation_required' },
      });
      throw new AppException(
        'Explicit confirmation is required to merge identities',
        ErrorCode.BAD_REQUEST,
        HttpStatus.BAD_REQUEST,
      );
    }

    const targetUser = await this.userService.findById(actorUserId);
    if (!targetUser || !targetUser.is_active) {
      this.recordAudit({
        id: auditId,
        timestamp,
        actorUserId,
        sourceAnonymousUserId,
        targetUserId: actorUserId,
        outcome: 'failure',
        details: { reason: 'unauthorized_actor' },
      });
      throw new AppException(
        'Authenticated account not found or inactive',
        ErrorCode.AUTH_UNAUTHORIZED,
        HttpStatus.UNAUTHORIZED,
      );
    }

    const sourceAnonymousUser =
      await this.anonymousUserService.findById(sourceAnonymousUserId);
    if (!sourceAnonymousUser) {
      this.recordAudit({
        id: auditId,
        timestamp,
        actorUserId,
        sourceAnonymousUserId,
        targetUserId: actorUserId,
        outcome: 'failure',
        details: { reason: 'source_not_found' },
      });
      throw new AppException(
        'Anonymous identity not found',
        ErrorCode.NOT_FOUND,
        HttpStatus.NOT_FOUND,
      );
    }

    if (
      sourceAnonymousUser.ownerUserId !== null &&
      sourceAnonymousUser.ownerUserId !== actorUserId
    ) {
      this.recordAudit({
        id: auditId,
        timestamp,
        actorUserId,
        sourceAnonymousUserId,
        targetUserId: actorUserId,
        outcome: 'failure',
        details: {
          reason: 'source_owned_by_other',
          ownerUserId: sourceAnonymousUser.ownerUserId,
        },
      });
      throw new AppException(
        'Anonymous identity is owned by another account',
        ErrorCode.AUTH_FORBIDDEN,
        HttpStatus.FORBIDDEN,
      );
    }

    const conflicts = await this.detectMergeConflicts(
      sourceAnonymousUserId,
      actorUserId,
    );

    const resolutionMap = new Map<string, MergeResolution>();
    for (const r of confirmation.resolutions ?? []) {
      resolutionMap.set(r.conflictId, r);
    }

    const unresolved = conflicts.filter((c) => !resolutionMap.has(conflictId(c)));
    if (unresolved.length > 0) {
      this.recordAudit({
        id: auditId,
        timestamp,
        actorUserId,
        sourceAnonymousUserId,
        targetUserId: actorUserId,
        outcome: 'failure',
        details: {
          reason: 'unresolved_conflicts',
          conflicts: unresolved.map(conflictId),
        },
      });
      throw new AppException(
        'Unresolved merge conflicts must be resolved before merging',
        ErrorCode.CONFLICT,
        HttpStatus.CONFLICT,
      );
    }

    const snapshot = await this.captureMergeSnapshot(
      sourceAnonymousUserId,
      actorUserId,
    );

    try {
      const transferred = await this.applyMergeTransfer(
        sourceAnonymousUserId,
        actorUserId,
        conflicts,
        resolutionMap,
      );

      await this.anonymousUserService.assignOwner(
        sourceAnonymousUserId,
        actorUserId,
      );

      this.recordAudit({
        id: auditId,
        timestamp,
        actorUserId,
        sourceAnonymousUserId,
        targetUserId: actorUserId,
        outcome: 'success',
        details: { transferred, conflicts: conflicts.length },
      });

      this.analyticsEventService
        ?.record({
          eventName: 'anonymous_identity_merged',
          actorId: `user:${actorUserId}`,
          metadata: { conflicts: conflicts.length },
        })
        .catch((err) =>
          this.logger.warn(
            `Failed to record merge analytics: ${
              err instanceof Error ? err.message : String(err)
            }`,
          ),
        );

      return {
        success: true,
        targetUserId: actorUserId,
        sourceAnonymousUserId,
        transferred,
        conflicts,
        auditId,
        rolledBack: false,
      };
    } catch (error) {
      await this.rollbackMerge(snapshot);
      this.recordAudit({
        id: auditId,
        timestamp,
        actorUserId,
        sourceAnonymousUserId,
        targetUserId: actorUserId,
        outcome: 'rollback',
        details: {
          reason: error instanceof Error ? error.message : 'unknown',
        },
      });
      throw new AppException(
        'Merge failed and was rolled back',
        ErrorCode.INTERNAL_SERVER_ERROR,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  getMergeAuditLog(actorUserId: number): MergeAuditEntry[] {
    return this.mergeAuditLog.filter((e) => e.actorUserId === actorUserId);
  }

  private recordAudit(entry: MergeAuditEntry): void {
    this.mergeAuditLog.push(entry);
    this.logger.log(`identity-merge audit ${entry.outcome}`, {
      auditId: entry.id,
      actorUserId: maskUserId(entry.actorUserId),
      sourceAnonymousUserId: entry.sourceAnonymousUserId,
      outcome: entry.outcome,
    });
  }

  private async detectMergeConflicts(
    sourceAnonymousUserId: string,
    targetUserId: number,
  ): Promise<MergeConflict[]> {
    const conflicts: MergeConflict[] = [];

    const sourceUsername =
      await this.anonymousUserService.getDisplayName(sourceAnonymousUserId);
    const targetUsername = await this.userService.getUsername(targetUserId);
    if (sourceUsername && targetUsername && sourceUsername !== targetUsername) {
      conflicts.push({
        type: 'username',
        sourceId: sourceAnonymousUserId,
        targetId: String(targetUserId),
        details: { sourceUsername, targetUsername },
      });
    }

    const sourceCounts = await this.anonymousUserService.getActivityCounts(
      sourceAnonymousUserId,
    );
    const targetCounts = await this.userService.getActivityCounts(targetUserId);

    const check = (
      type: MergeConflict['type'],
      sourceCount: number,
      targetCount: number,
    ) => {
      if (sourceCount > 0 && targetCount > 0) {
        conflicts.push({
          type,
          sourceId: sourceAnonymousUserId,
          targetId: String(targetUserId),
          details: { sourceCount, targetCount },
        });
      }
    };

    check('message', sourceCounts.messages, targetCounts.messages);
    check('draft', sourceCounts.drafts, targetCounts.drafts);
    check('tip', sourceCounts.tips, targetCounts.tips);
    check('anchor', sourceCounts.anchors, targetCounts.anchors);

    return conflicts;
  }

  private async captureMergeSnapshot(
    sourceAnonymousUserId: string,
    targetUserId: number,
  ): Promise<{
    sourceOwnerUserId: number | null;
    targetCounts: Record<string, number>;
  }> {
    const source = await this.anonymousUserService.findById(sourceAnonymousUserId);
    const targetCounts = await this.userService.getActivityCounts(targetUserId);
    return {
      sourceOwnerUserId: source ? source.ownerUserId : null,
      targetCounts: targetCounts as unknown as Record<string, number>,
    };
  }

  private async applyMergeTransfer(
    sourceAnonymousUserId: string,
    targetUserId: number,
    conflicts: MergeConflict[],
    resolutionMap: Map<string, MergeResolution>,
  ): Promise<Record<string, number>> {
    const transferred: Record<string, number> = {
      messages: 0,
      drafts: 0,
      tips: 0,
      anchors: 0,
    };

    const ownership = await this.anonymousUserService.getOwnershipRecord(
      sourceAnonymousUserId,
    );

    for (const conflict of conflicts) {
      const resolution = resolutionMap.get(conflictId(conflict))!;
      await this.applyConflictResolution(
        conflict,
        resolution,
        sourceAnonymousUserId,
        targetUserId,
        ownership,
      );
    }

    const transferResult = await this.anonymousUserService.transferAssets(
      sourceAnonymousUserId,
      targetUserId,
    );
    transferred.messages = transferResult.messages;
    transferred.drafts = transferResult.drafts;
    transferred.tips = transferResult.tips;
    transferred.anchors = transferResult.anchors;

    return transferred;
  }

  private async applyConflictResolution(
    conflict: MergeConflict,
    resolution: MergeResolution,
    sourceAnonymousUserId: string,
    targetUserId: number,
    ownership: Record<string, unknown>,
  ): Promise<void> {
    switch (conflict.type) {
      case 'username':
        if (resolution.resolution === 'use_source') {
          await this.userService.setUsername(
            targetUserId,
            String(conflict.details.sourceUsername),
          );
        }
        break;
      case 'message':
        await this.anonymousUserService.resolveConflict(
          sourceAnonymousUserId,
          targetUserId,
          'message',
          resolution.resolution,
        );
        break;
      case 'draft':
        await this.anonymousUserService.resolveConflict(
          sourceAnonymousUserId,
          targetUserId,
          'draft',
          resolution.resolution,
        );
        break;
      case 'tip':
        await this.anonymousUserService.resolveConflict(
          sourceAnonymousUserId,
          targetUserId,
          'tip',
          resolution.resolution,
        );
        break;
      case 'anchor':
        await this.anonymousUserService.resolveConflict(
          sourceAnonymousUserId,
          targetUserId,
          'anchor',
          resolution.resolution,
        );
        break;
      default:
        break;
    }
    ownership[conflictId(conflict)] = resolution.resolution;
  }

  private async rollbackMerge(snapshot: {
    sourceOwnerUserId: number | null;
    targetCounts: Record<string, number>;
  }): Promise<void> {
    this.logger.warn(`Rolling back identity merge`, {
      sourceOwnerUserId: snapshot.sourceOwnerUserId,
    });
    await this.anonymousUserService.restoreOwner(
      sourceOwnerUserId !== null ? String(snapshot.sourceOwnerUserId) : '',
      snapshot.sourceOwnerUserId,
    );
  }
}

function conflictId(conflict: MergeConflict): string {
  return `${conflict.type}:${conflict.sourceId}:${conflict.targetId}`;
}
