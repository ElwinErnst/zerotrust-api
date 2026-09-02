import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import type { AuthUser } from '../auth/types';
import { JwtVerifyService } from '../auth/jwt-verify.service';
import { PolicyGenerateGuard } from './policy-generate.guard';

const TENANT = '11111111-1111-1111-1111-111111111111';

function contextFor(authHeader: string | undefined): ExecutionContext {
  const req = { headers: authHeader ? { authorization: authHeader } : {} };
  return {
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

function guardWith(
  verify: (h: string | undefined) => AuthUser,
): PolicyGenerateGuard {
  const jwt = { verifyBearer: verify } as unknown as JwtVerifyService;
  return new PolicyGenerateGuard(jwt);
}

const owner: AuthUser = { sub: 'u1', tenantId: TENANT, roles: ['OWNER'] };
const admin: AuthUser = { sub: 'u2', tenantId: TENANT, roles: ['ADMIN'] };
const member: AuthUser = { sub: 'u3', tenantId: TENANT, roles: ['MEMBER'] };

describe('PolicyGenerateGuard', () => {
  it('allows an OWNER', () => {
    expect(guardWith(() => owner).canActivate(contextFor('Bearer x'))).toBe(
      true,
    );
  });

  it('allows an ADMIN', () => {
    expect(guardWith(() => admin).canActivate(contextFor('Bearer x'))).toBe(
      true,
    );
  });

  it('rejects a MEMBER', () => {
    expect(() =>
      guardWith(() => member).canActivate(contextFor('Bearer x')),
    ).toThrow(ForbiddenException);
  });

  it('rejects a missing/invalid token (deny by default)', () => {
    const guard = guardWith(() => {
      throw new UnauthorizedException('Missing bearer token');
    });
    expect(() => guard.canActivate(contextFor(undefined))).toThrow(
      UnauthorizedException,
    );
  });
});
