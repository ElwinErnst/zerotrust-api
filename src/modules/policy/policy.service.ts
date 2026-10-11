import { Injectable, Logger } from '@nestjs/common';
import { AuthDirectoryService } from '../../common/modules/auth-directory/auth-directory.service';
import { TenantPolicyProvider } from './tenant-policy-provider';
import { evaluatePolicySet } from './policy-evaluator';
import { PolicyDecision, PolicyInput } from './types';
import { VAULT_UPSTREAM_NAME } from '../../config/upstreams.config';

@Injectable()
export class PolicyService {
  private readonly logger = new Logger(PolicyService.name);

  constructor(
    private readonly authDirectory: AuthDirectoryService,
    private readonly tenantPolicy: TenantPolicyProvider,
  ) {}

  async decide(input: PolicyInput): Promise<PolicyDecision> {
    // Layer 1: the tenant's published PolicySet, owned by auth-api and read
    // (cached) here. It takes precedence over the legacy hardcoded rules.
    //  - error → fail closed (deny); never fall through on an outage.
    //  - none  → no custom policy; fall through to entitlement/role rules.
    // Resolve the tenant's published policy up front. On an outage we must
    // fail closed before doing anything else.
    const resolution = await this.tenantPolicy.resolve(input.tenantId);
    if (resolution.status === 'error') {
      return { allow: false, reason: 'Policy service unavailable' };
    }

    // Entitlements are the plan ceiling and are ALWAYS enforced — a custom
    // policy may only restrict access further, never grant beyond the plan.
    const entitlements = await this.authDirectory.getTenantEntitlements(
      input.tenantId,
    );
    if (!entitlements) {
      return { allow: false, reason: 'Tenant entitlements not found' };
    }

    const isApiClient = !this.hasHumanRole(input.roles);

    // A published custom PolicySet (when the plan includes ZT policies) takes
    // precedence for ANY upstream — the evaluator matches rules by
    // `when.upstream`. Evaluated within the per-upstream ceilings below.
    const hasCustomPolicy =
      resolution.status === 'found' && entitlements.features.ztPolicies;

    if (input.upstream === VAULT_UPSTREAM_NAME) {
      // Vault feature ceilings — always enforced, vault only.
      if (!entitlements.features.vaults) {
        return {
          allow: false,
          reason: 'Vault access is not enabled for this tenant plan',
        };
      }
      if (isApiClient && !entitlements.features.apiVault) {
        return {
          allow: false,
          reason: 'Vault API Pack is not enabled for this tenant',
        };
      }

      if (hasCustomPolicy && resolution.status === 'found') {
        const decision = evaluatePolicySet(resolution.policySet, input);
        this.logger.debug(
          `tenant=${input.tenantId} upstream=vault matched policy v${resolution.version}: ${JSON.stringify(decision)}`,
        );
        return decision;
      }

      // Built-in vault RBAC fallback (no custom policy, or plan lacks ZT policies).
      if (isApiClient) {
        return this.allowApiClientVaultRoute(input);
      }
      if (input.path.startsWith('/documents')) {
        if (input.method === 'GET') return this.requireRole(input, 'MEMBER');
        if (input.method === 'POST') return this.requireRole(input, 'ADMIN');
        if (input.method === 'DELETE') return this.requireRole(input, 'ADMIN');
      }
      return this.requireRole(input, 'MEMBER');
    }

    // Registered (non-vault) upstream: no vault ceilings or vault RBAC routes. A
    // published policy decides; otherwise a coarse default — require a human role,
    // which denies API clients and anonymous callers unless a policy explicitly
    // allows them.
    if (hasCustomPolicy && resolution.status === 'found') {
      const decision = evaluatePolicySet(resolution.policySet, input);
      this.logger.debug(
        `tenant=${input.tenantId} upstream=${input.upstream} matched policy v${resolution.version}: ${JSON.stringify(decision)}`,
      );
      return decision;
    }
    return this.requireRole(input, 'MEMBER');
  }

  private requireRole(input: PolicyInput, role: string): PolicyDecision {
    if (this.hasRequiredRole(input.roles, role)) return { allow: true };
    return { allow: false, reason: `Missing role ${role}` };
  }

  private hasRequiredRole(userRoles: string[], requiredRole: string): boolean {
    const hierarchy: Record<string, number> = {
      MEMBER: 1,
      ADMIN: 2,
      OWNER: 3,
    };

    const requiredLevel = hierarchy[requiredRole] ?? Number.MAX_SAFE_INTEGER;

    return userRoles.some((role) => {
      const level = hierarchy[role];
      return typeof level === 'number' && level >= requiredLevel;
    });
  }

  private hasHumanRole(userRoles: string[]): boolean {
    return userRoles.some((role) =>
      ['MEMBER', 'ADMIN', 'OWNER'].includes(role),
    );
  }

  private allowApiClientVaultRoute(input: PolicyInput): PolicyDecision {
    const method = input.method.toUpperCase();
    const path = input.path;

    const allowed =
      (method === 'GET' && path === '/vaults') ||
      (method === 'POST' && path === '/documents') ||
      (method === 'GET' && path === '/documents') ||
      (method === 'GET' && /^\/documents\/[^/]+\/download$/.test(path));

    if (allowed) {
      return { allow: true };
    }

    return {
      allow: false,
      reason: 'API client is not allowed on this Vault route',
    };
  }
}
