import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import type { AuthUser } from '../auth/types';
import { JwtVerifyService } from '../auth/jwt-verify.service';
import { PolicyAdminGuard } from './policy-admin.guard';

const TENANT = '11111111-1111-1111-1111-111111111111';

function contextFor(
  authHeader: string | undefined,
  tenantId: string,
): ExecutionContext {
  const req = {
    headers: authHeader ? { authorization: authHeader } : {},
    params: { tenantId },
  };
  return {
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

function guardWith(verify: (h: string | undefined) => AuthUser): {
  guard: PolicyAdminGuard;
} {
  const jwt = { verifyBearer: verify } as unknown as JwtVerifyService;
  return { guard: new PolicyAdminGuard(jwt) };
}

const owner: AuthUser = { sub: 'u1', tenantId: TENANT, roles: ['OWNER'] };
const admin: AuthUser = { sub: 'u2', tenantId: TENANT, roles: ['ADMIN'] };
const member: AuthUser = { sub: 'u3', tenantId: TENANT, roles: ['MEMBER'] };

describe('PolicyAdminGuard', () => {
  it('allows an OWNER of the path tenant', () => {
    const { guard } = guardWith(() => owner);
    expect(guard.canActivate(contextFor('Bearer x', TENANT))).toBe(true);
  });

  it('allows an ADMIN of the path tenant', () => {
    const { guard } = guardWith(() => admin);
    expect(guard.canActivate(contextFor('Bearer x', TENANT))).toBe(true);
  });

  it('rejects a MEMBER (not an admin)', () => {
    const { guard } = guardWith(() => member);
    expect(() => guard.canActivate(contextFor('Bearer x', TENANT))).toThrow(
      ForbiddenException,
    );
  });

  it('rejects a valid admin of a DIFFERENT tenant (tenant scope)', () => {
    const otherTenant: AuthUser = {
      sub: 'u4',
      tenantId: '22222222-2222-2222-2222-222222222222',
      roles: ['OWNER'],
    };
    const { guard } = guardWith(() => otherTenant);
    expect(() => guard.canActivate(contextFor('Bearer x', TENANT))).toThrow(
      ForbiddenException,
    );
  });

  it('rejects a missing/invalid token (deny by default)', () => {
    const { guard } = guardWith(() => {
      throw new UnauthorizedException('Missing bearer token');
    });
    expect(() => guard.canActivate(contextFor(undefined, TENANT))).toThrow(
      UnauthorizedException,
    );
  });
});
