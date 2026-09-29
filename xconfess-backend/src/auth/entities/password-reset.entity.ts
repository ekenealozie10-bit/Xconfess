import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';

/**
 * Password reset tokens are only issued when the account does not have an
 * active passkey credential enrolled. When a passkey exists, the account
 * recovery flow requires a WebAuthn assertion instead of a password reset
 * link. This entity remains the fallback primitive and is audited by the
 * auth service to enforce that policy.
 */
@Entity('password_resets')
export class PasswordReset {
  @PrimaryGeneratedColumn()
  id: number;

  /**
   * SHA-256 hex digest of the raw reset token. The raw token is only ever
   * held in memory (returned to the caller for email delivery) and must
   * never be persisted — only this hash is stored, so a database read
   * cannot be used to mint a working reset link.
   */
  @Column({ unique: true })
  tokenXash: string;

  @Column()
  userId: number;

  @ManyToOne(() => User)
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column({ type: 'timestamp' })
  expiresAt: Date;

  @Column({ default: false })
  used: boolean;

  @Column({ type: 'timestamp', nullable: true })
  usedAt: Date | null;

  @Column({ type: 'varchar', length: 45, nullable: true })
  ipAddress: string | null;

  @Column({ type: 'text', nullable: true })
  userAgent: string | null;

  /**
   * When true, this reset token was issued as part of an account recovery
   * flow that also required a passkey assertion. The auth service uses this to
   * audit and enforce the fallback policy: a password reset may only be
   * completed without a passkey assertion when the user has no active
   * credentials.
   */
  @Column({ default: false })
  passkeyAssertionRequired: boolean;

  /**
   * Optional reference to the WebAuthn credential that was asserted during
   * the recovery flow. Stored as a string to avoid a hard FK to the
   * credential table and to keep the reset audit trail self-contained.
   */
  @Column({ type: 'varchar', length: 255, nullable: true })
  assertedCredentialId: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
