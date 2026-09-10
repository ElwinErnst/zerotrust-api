import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
} from 'typeorm';
import type {
  AuditActorType,
  AuditCategory,
  AuditOutcome,
  AuditSystem,
} from '../audit-event.types';

/**
 * A normalized audit event owned by zerotrust-api. Queried per tenant, newest
 * first, so the hot path is (tenant_id, occurred_at).
 */
@Index(['tenantId', 'occurredAt'])
@Entity('audit_events')
export class AuditEvent {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid', name: 'tenant_id' })
  tenantId!: string;

  @Column({ type: 'varchar', length: 16 })
  system!: AuditSystem;

  @Column({ type: 'varchar', length: 16 })
  category!: AuditCategory;

  @Column({ type: 'varchar', length: 64 })
  action!: string;

  @Column({ type: 'varchar', length: 16, name: 'actor_type', nullable: true })
  actorType!: AuditActorType | null;

  @Column({ type: 'uuid', name: 'actor_id', nullable: true })
  actorId!: string | null;

  @Column({ type: 'varchar', length: 32, name: 'resource_type', nullable: true })
  resourceType!: string | null;

  @Column({ type: 'varchar', length: 128, name: 'resource_id', nullable: true })
  resourceId!: string | null;

  @Column({ type: 'varchar', length: 16 })
  outcome!: AuditOutcome;

  @Column({ type: 'jsonb', nullable: true })
  detail!: Record<string, unknown> | null;

  @CreateDateColumn({ name: 'occurred_at', type: 'timestamptz' })
  occurredAt!: Date;
}
