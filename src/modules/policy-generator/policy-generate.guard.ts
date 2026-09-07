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
 * Authorizes the LLM policy generator (`POST /policies/generate`).
 *
 * Deny-by-default: requires a valid access token and an OWNER/ADMIN caller.
 * The generator does not persist (its output is published through auth-api's
 * tenant-scoped policy admin API), so this guard's job is to stop unauthenticated
 * use of an LLM-backed endpoint (cost/abuse), not to enforce tenant scope. The
 * request is scoped by `tenantSlug` in the body; binding that to the caller's
 * tenant is a separate, optional follow-up.
 */
@Injectable()
export class PolicyGenerateGuard implements CanActivate {
  constructor(private readonly jwt: JwtVerifyService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context
      .switchToHttp()
      .getRequest<Request & { user?: AuthUser }>();

    const authHeader = req.headers['authorization'];
    const bearer = typeof authHeader === 'string' ? authHeader : undefined;

    // Throws UnauthorizedException (401) on a missing/invalid/expired token.
    const user = this.jwt.verifyBearer(bearer);

    if (!user.roles.some((role) => ADMIN_ROLES.has(role))) {
      throw new ForbiddenException('Policy generation requires OWNER or ADMIN');
    }

    req.user = user;
    return true;
  }
}
