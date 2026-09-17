import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuditService } from './audit.service';

const PURGE_INTERVAL_MS = 24 * 60 * 60 * 1000;

/**
 * Keeps the decision log bounded. Every gateway request writes an audit row, so
 * without this the table grows without limit. Runs a purge on boot and then
 * daily, deleting events older than `zt.auditRetentionDays` (0 disables it).
 *
 * Dependency-free on purpose (no @nestjs/schedule): a plain interval is enough
 * for a retention sweep, and the timer is unref'd so it never keeps the process
 * alive on its own.
 */
@Injectable()
export class AuditRetentionService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AuditRetentionService.name);
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly audit: AuditService,
    private readonly config: ConfigService,
  ) {}

  onModuleInit(): void {
    const retentionDays = this.config.get<number>('zt.auditRetentionDays') ?? 0;
    if (retentionDays <= 0) {
      this.logger.log('Audit retention disabled (zt.auditRetentionDays <= 0)');
      return;
    }

    this.logger.log(
      `Audit retention active: purging decision log older than ${retentionDays} day(s), daily`,
    );

    void this.purge(retentionDays);
    this.timer = setInterval(() => {
      void this.purge(retentionDays);
    }, PURGE_INTERVAL_MS);
    // Do not let the retention timer keep the process alive by itself.
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Fail-safe: retention must never crash the service. */
  private async purge(retentionDays: number): Promise<void> {
    try {
      const removed = await this.audit.purgeOlderThan(retentionDays);
      if (removed > 0) {
        this.logger.log(`Purged ${removed} audit event(s) past retention`);
      }
    } catch (error) {
      this.logger.error(
        `Audit retention purge failed: ${
          error instanceof Error ? error.message : 'unknown error'
        }`,
      );
    }
  }
}
