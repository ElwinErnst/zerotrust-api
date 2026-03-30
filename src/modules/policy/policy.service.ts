import { Injectable } from '@nestjs/common';
import { PolicyDecision, PolicyInput } from './types';

@Injectable()
export class PolicyService {
  decide(input: PolicyInput): PolicyDecision {
    // MVP: reglas para Vault
    if (input.upstream === 'vault') {
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
}
