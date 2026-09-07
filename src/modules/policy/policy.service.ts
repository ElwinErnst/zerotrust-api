import { Injectable, Logger } from '@nestjs/common';
import { AuthDirectoryService } from '../../common/modules/auth-directory/auth-directory.service';
import { TenantPolicyProvider } from './tenant-policy-provider';
import { evaluatePolicySet } from './policy-evaluator';
import { PolicyDecision, PolicyInput } from './types';

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
    const resolution = await this.tenantPolicy.resolve(input.tenantId);
    if (resolution.status === 'error') {
      return { allow: false, reason: 'Policy service unavailable' };
    }
    if (resolution.status === 'found') {
      const decision = evaluatePolicySet(resolution.policySet, input);
      this.logger.debug(
        `tenant=${input.tenantId} matched compiled policy v${resolution.version}: ${JSON.stringify(decision)}`,
      );
      return decision;
    }

    const entitlements = await this.authDirectory.getTenantEntitlements(
      input.tenantId,
    );

    if (!entitlements) {
      return { allow: false, reason: 'Tenant entitlements not found' };
    }

    const isApiClient = !this.hasHumanRole(input.roles);

    // MVP: reglas para Vault
    if (input.upstream === 'vault') {
      if (!entitlements.features.vaults) {
        return {
          allow: false,
          reason: 'Vault access is not enabled for this tenant plan',
        };
      }

      // Los clientes API no comparten la misma política que el workspace humano.
      // Si el token no trae roles humanos, tratamos el request como integración externa.
      if (isApiClient) {
        if (!entitlements.features.apiVault) {
          return {
            allow: false,
            reason: 'Vault API Pack is not enabled for this tenant',
          };
        }

        return this.allowApiClientVaultRoute(input);
      }

      // Ejemplos:
      // - listar docs: MEMBER
      // - subir/borrar: ADMIN
      if (input.path.startsWith('/documents')) {
        if (input.method === 'GET') return this.requireRole(input, 'MEMBER');
        if (input.method === 'POST') return this.requireRole(input, 'ADMIN');
        if (input.method === 'DELETE') return this.requireRole(input, 'ADMIN');
      }

      // default: MEMBER para el resto (ajustable)
      return this.requireRole(input, 'MEMBER');
    }

    return { allow: false, reason: 'Unknown upstream' };
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
