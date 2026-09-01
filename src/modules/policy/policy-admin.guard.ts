import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import { JwtVerifyService } from '../auth/jwt-verify.service';
import type { AuthUser } from '../auth/types';

const ADMIN_ROLES = new Set(['OWNER', 'ADMIN']);

/**
 * Authorizes tenant policy administration on `/policies/:tenantId`.
 *
 * Deny-by-default: requires a valid access token (JwtVerifyService throws 401
 * on a missing/invalid one), and the caller must be an OWNER or ADMIN of the
 * SAME tenant named in the path. Without this guard the endpoint was open —
 * anyone reaching the gateway could overwrite a tenant's compiled policy and,
 * because a stored policy takes precedence in PolicyService.decide, bypass all
 * access control for that tenant.
 */
@Injectable()
export class PolicyAdminGuard implements CanActivate {
  constructor(private readonly jwt: JwtVerifyService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context
      .switchToHttp()
      .getRequest<
        Request & { user?: AuthUser; params: { tenantId?: string } }
      >();

    const authHeader = req.headers['authorization'];
    const bearer = typeof authHeader === 'string' ? authHeader : undefined;

    // Throws UnauthorizedException (401) on a missing/invalid/expired token.
    const user = this.jwt.verifyBearer(bearer);

    const tenantId = req.params?.tenantId;
    if (!tenantId || user.tenantId !== tenantId) {
      throw new ForbiddenException('Policy admin is scoped to your own tenant');
    }

    if (!user.roles.some((role) => ADMIN_ROLES.has(role))) {
      throw new ForbiddenException('Policy admin requires OWNER or ADMIN');
    }

    req.user = user;
    return true;
  }
}
