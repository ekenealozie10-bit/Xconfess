import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';

@Entity('password_resets')
@Index(['selectorHash'])
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

  /**
   * Selector prefix of the raw token (e.g. first 16 hex chars). Stored for
   * operational lookup and audit correlation without revealing the full
   * token material. Not sufficient to reconstruct the token.
   */
  @Column({ type: 'varchar', length: 32, nullable: true })
  selectorHash: string | null;

  @Column()
  userId: number;

  @ManyToOne(() => User)
  @JoinColumn({ token: 'userId' })
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

  @CreateDateColumn()
  createdAt: Date;
}
