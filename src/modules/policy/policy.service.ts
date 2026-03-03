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
    if (input.roles.includes(role)) return { allow: true };
    return { allow: false, reason: `Missing role ${role}` };
  }
}
