import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditEvent } from './entities/audit-event.entity';
import type { AuditEventInput } from './audit-event.types';

export type ListAuditEventsOptions = {
  page?: number;
  limit?: number;
};

export type ListAuditEventsResult = {
  items: AuditEvent[];
  total: number;
  page: number;
  limit: number;
};

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(
    @InjectRepository(AuditEvent)
    private readonly repo: Repository<AuditEvent>,
  ) {}

  /**
   * Record an audit event. Fail-open by design: on the gateway hot path this is
   * called fire-and-forget (never awaited), so a decision is enforced and the
   * request served even if its audit row fails to persist. Errors are logged,
   * never thrown — this method must not reject.
   */
  async emit(input: AuditEventInput): Promise<void> {
    try {
      const event = this.repo.create({
        tenantId: input.tenantId,
        system: input.system,
        category: input.category,
        action: input.action,
        actorType: input.actorType ?? null,
        actorId: input.actorId ?? null,
        resourceType: input.resourceType ?? null,
        resourceId: input.resourceId ?? null,
        outcome: input.outcome,
        detail: input.detail ?? null,
      });
      await this.repo.save(event);
    } catch (error) {
      this.logger.error(
        `Failed to record audit event '${input.action}' for tenant=${input.tenantId}: ${
          error instanceof Error ? error.message : 'unknown error'
        }`,
      );
    }
  }

  /**
   * Delete events older than `retentionDays`, keeping the high-volume decision
   * log bounded. Returns the number of rows removed. A retention of 0 (or less)
   * is a no-op so purging can be disabled via config.
   */
  async purgeOlderThan(retentionDays: number): Promise<number> {
    if (!Number.isFinite(retentionDays) || retentionDays <= 0) return 0;

    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    const result = await this.repo
      .createQueryBuilder()
      .delete()
      .where('occurred_at < :cutoff', { cutoff })
      .execute();

    return result.affected ?? 0;
  }

  async list(
    tenantId: string,
    options: ListAuditEventsOptions = {},
  ): Promise<ListAuditEventsResult> {
    const page = Math.max(1, Math.floor(options.page ?? 1));
    const limit = Math.min(
      MAX_LIMIT,
      Math.max(1, Math.floor(options.limit ?? DEFAULT_LIMIT)),
    );

    const [items, total] = await this.repo.findAndCount({
      where: { tenantId },
      order: { occurredAt: 'DESC' },
      take: limit,
      skip: (page - 1) * limit,
    });

    return { items, total, page, limit };
  }
}
