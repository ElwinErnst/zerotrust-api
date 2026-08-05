import { Injectable, Logger } from '@nestjs/common';
import type { PolicySet } from '../policy-generator/schema/policy.schema';

type StoredPolicy = {
  policySet: PolicySet;
  updatedAt: Date;
};

/**
 * In-memory per-tenant policy store. Populated by the generator endpoint
 * (or by an admin `PUT /policies/:tenantId`) and consumed by `PolicyService`
 * as the first evaluation source.
 *
 * State is intentionally NOT persisted here — the zt-api is otherwise
 * stateless. A restart drops all policy sets and falls back to the hard-
 * coded rules in `policy.service.ts`. Persistence belongs in `auth-api`
 * (as a per-tenant column) so it survives gateway restarts; wiring that
 * is a follow-up slice.
 */
@Injectable()
export class PolicyStoreService {
  private readonly logger = new Logger(PolicyStoreService.name);
  private readonly byTenant = new Map<string, StoredPolicy>();

  set(tenantId: string, policySet: PolicySet): StoredPolicy {
    const stored: StoredPolicy = { policySet, updatedAt: new Date() };
    this.byTenant.set(tenantId, stored);
    this.logger.log(
      `policy set stored for tenant=${tenantId} rules=${policySet.rules.length} default=${policySet.default}`,
    );
    return stored;
  }

  get(tenantId: string): StoredPolicy | null {
    return this.byTenant.get(tenantId) ?? null;
  }

  remove(tenantId: string): boolean {
    const removed = this.byTenant.delete(tenantId);
    if (removed) {
      this.logger.log(`policy set cleared for tenant=${tenantId}`);
    }
    return removed;
  }

  list(): Array<{ tenantId: string } & StoredPolicy> {
    return Array.from(this.byTenant.entries()).map(([tenantId, s]) => ({
      tenantId,
      ...s,
    }));
  }
}
