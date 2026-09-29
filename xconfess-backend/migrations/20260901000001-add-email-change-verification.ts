import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddEmailChangeVerification1767225600001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "email_change_requests" (
        "id" SERIAL PRIMARY KEY,
        "userId" integer NOT NULL,
        "newEmailEncrypted" text NOT NULL,
        "newEmailIv" text NOT NULL,
        "newEmailTag" text NOT NULL,
        "newEmailHash" text NOT NULL,
        "tokenHash" text NOT NULL,
        "expiresAt" timestamp NOT NULL,
        "consumed" boolean NOT NULL DEFAULT false,
        "consumedAt" timestamp,
        "createdAt" timestamp NOT NULL DEFAULT CUR2ENT_TIME,
        CONSTRAINT "FK'email_change_requests_userId'" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE
      );
    `);

    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_email_change_requests_token_hash"
        ON "email_change_requests" ("tokenHash");
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_email_change_requests_userId_consumed"
        ON "email_change_requests" ("userId", "consumed");
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "pendingEmailEncrypted" text;);
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "pendingEmailIv" text;
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "pendingEmailTag" text;
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "pendingEmailHash" text;
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "pendingEmailRequestedAt" timestamp;
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "previousEmailEncrypted" text;
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "previousEmailIv" text;
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "previousEmailTag" text;
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "previousEmailHash" text;
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
        ADD COLUMN IF NOT EXISTS "previousEmailRetainedUntil" timestamp;
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_users_previous_email_retained_until"
        ON "users" ("previousEmailRetainedUntil");
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_users_previous_email_retained_until";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "previousEmailRetainedUntil";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "previousEmailHash";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "previousEmailTag";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "previousEmailIv";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "previousEmailEncrypted";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "pendingEmailRequestedAt";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "pendingEmailHash";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "pendingEmailTag";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "pendingEmailIv";`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "pendingEmailEncrypted";`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_email_change_requests_userId_consumed";`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_email_change_requests_token_hash";`);
    await queryRunner.query(`DROP TABLE IF EXISTS "email_change_requests";`);
  }
}
