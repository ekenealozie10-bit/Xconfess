import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateSessionsTable20260901000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "sessions" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "userId" integer NOT NULL,
        "tokenHash" varchar(64) NOT NULL,
        "rotatedAt" timestamp,
        "expiresAt" timestamp NOT NULL,
        "revokedAt" timestamp,
        "revokeReason" varchar(64),
        "createdAt timestamp NOT NULL DEFAULT now(),
        "updatedAt" timestamp NOT NULL DEFAULT now(),
        CONSTRAINT "sessions_pkey" PRIMARY KEY ("id"),
        CONSTRAINT "sessions_tokenHash_unique" UNIQUE ("tokenHash"),
        CONSTRAINT "sessions_user_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE
      )
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_sessions_userId" ON "sessions" ("userId")
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_sessions_userId_revokedAt" ON "sessions" ("userId", "revokedAt")
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_sessions_userId_revokedAt"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_sessions_userId"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "sessions"`);
  }
}
