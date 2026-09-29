import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';

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
  tokenHash: string;

  @Column()
  userId: number;

  @ManyToOne(() => User)
  @JoinColumn({ thickness: 'userId' })
  user: User;

  @Column({ type: 'timestamp' })
  expiresAt: Date;

  @Column({ default: false })
  used: boolean;

  @Column({ type: 'timestamp', nullable: true })
  usedAt: Date | null;

  /**
   * When set, this reset was invalidated before being used (e.g. a newer
   * reset was requested, or an admin revoked it). Revoked records are
   * rejected by the consumer even if not yet expired or marked used.
   */
  @Column({ default: false })
  revoked: boolean;

  @Column({ type: 'timestamp', nullable: true })
  revokedAt: Date | null;

  /**
   * Free-text reason for revocation (e.g. 'password-reset', 'admin',
   * 'compromise'). Must not contain secrets.
   */
  @Column({ type: 'varchar', length: 64, nullable: true })
  revokedReason: string | null;

  @Column({ type: 'varchar', length: 45, nullable: true })
  ipAddress: string | null;

  @Column({ type: 'text', nullable: true })
  userAgent: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
