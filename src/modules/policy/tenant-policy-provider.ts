import { Injectable, Logger } from '@nestjs/common';
import { AuthDirectoryService } from '../../common/modules/auth-directory/auth-directory.service';
import {
  policySetSchema,
  type PolicySet,
} from '../policy-generator/schema/policy.schema';

export type PolicyResolution =
  | { status: 'found'; policySet: PolicySet; version: number }
  | { status: 'none' }
  | { status: 'error' };

type CacheEntry = {
  resolution: Extract<PolicyResolution, { status: 'found' | 'none' }>;
  expiresAt: number;
};

const DEFAULT_TTL_MS = Number(process.env.ZT_POLICY_CACHE_TTL_MS ?? 30_000);

/**
 * Reads a tenant's published policy from auth-api (the source of truth) and
 * caches it briefly. Fail-safe by design:
 *  - `found`  → a valid published policy set (schema re-validated here).
 *  - `none`   → auth-api has no policy for the tenant (404); caller falls back
 *               to entitlement/role rules.
 *  - `error`  → auth-api unreachable OR served an invalid policy; the caller
 *               MUST deny. Errors are never cached, so a transient outage
 *               recovers on the next request.
 */
@Injectable()
export class TenantPolicyProvider {
  private readonly logger = new Logger(TenantPolicyProvider.name);
  private readonly cache = new Map<string, CacheEntry>();
  // Not a constructor parameter: Nest cannot inject a primitive `number`, so a
  // second ctor arg would fail DI at boot. Read from env at construction.
  private readonly ttlMs = DEFAULT_TTL_MS;

  constructor(private readonly authDirectory: AuthDirectoryService) {}

  async resolve(tenantId: string): Promise<PolicyResolution> {
    const cached = this.cache.get(tenantId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.resolution;
    }

    let remote: { policySet: unknown; version: number } | null;
    try {
      remote = await this.authDirectory.getTenantPolicy(tenantId);
    } catch (error) {
      this.logger.warn(
        `Failed to fetch policy for tenant=${tenantId}; failing closed: ${
          error instanceof Error ? error.message : 'unknown error'
        }`,
      );
      return { status: 'error' };
    }

    if (!remote) {
      return this.store(tenantId, { status: 'none' });
    }

    const parsed = policySetSchema.safeParse(remote.policySet);
    if (!parsed.success) {
      this.logger.error(
        `Stored policy for tenant=${tenantId} failed validation; failing closed`,
      );
      return { status: 'error' };
    }

    return this.store(tenantId, {
      status: 'found',
      policySet: parsed.data,
      version: remote.version,
    });
  }

  private store(
    tenantId: string,
    resolution: Extract<PolicyResolution, { status: 'found' | 'none' }>,
  ): PolicyResolution {
    this.cache.set(tenantId, {
      resolution,
      expiresAt: Date.now() + this.ttlMs,
    });
    return resolution;
  }
}
