import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * 2b-2 — Zero Trust audit events (decision log).
 *
 * zerotrust-api's first table. Persists policy decisions (allow/deny) and any
 * other ZT audit events with the normalized shape (see audit-event.types.ts),
 * owned locally and exposed at GET /api/zt/audit-events. Read path is per
 * tenant, newest first → index (tenant_id, occurred_at). Uses gen_random_uuid()
 * (core in Postgres 13+) so no uuid-ossp extension is required on a fresh DB.
 */
export class AddAuditEvents1787700000000 implements MigrationInterface {
  name = 'AddAuditEvents1787700000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "audit_events" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "tenant_id" uuid NOT NULL,
        "system" character varying(16) NOT NULL,
        "category" character varying(16) NOT NULL,
        "action" character varying(64) NOT NULL,
        "actor_type" character varying(16),
        "actor_id" uuid,
        "resource_type" character varying(32),
        "resource_id" character varying(128),
        "outcome" character varying(16) NOT NULL,
        "detail" jsonb,
        "occurred_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
        CONSTRAINT "PK_audit_events" PRIMARY KEY ("id")
      )`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_audit_events_tenant_occurred" ON "audit_events" ("tenant_id", "occurred_at")`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "IDX_audit_events_tenant_occurred"`);
    await queryRunner.query(`DROP TABLE "audit_events"`);
  }
}
