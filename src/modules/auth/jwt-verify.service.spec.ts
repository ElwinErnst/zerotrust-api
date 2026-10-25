import { UnauthorizedException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import jwt from 'jsonwebtoken';
import { JwtVerifyService } from './jwt-verify.service';
import type { JwtConfig } from './types/jwt-config.type';

const CFG: JwtConfig = {
  issuer: 'http://localhost:3000',
  audience: 'vault-api',
  hs256Secret: 'test-secret',
};

const TENANT = '11111111-1111-1111-1111-111111111111';

function configServiceWith(cfg: JwtConfig | undefined): ConfigService {
  return { get: () => cfg } as unknown as ConfigService;
}

function signAccessToken(overrides: Record<string, unknown> = {}): string {
  const {
    issuer = CFG.issuer,
    audience = CFG.audience,
    secret = CFG.hs256Secret,
    expiresIn = '5m',
    ...claims
  } = overrides;

  return jwt.sign(
    {
      sub: 'user-1',
      tenantId: TENANT,
      roles: ['MEMBER'],
      type: 'access',
      ...claims,
    },
    secret as string,
    {
      issuer: issuer as string,
      audience: audience as string,
      expiresIn: expiresIn as jwt.SignOptions['expiresIn'],
      algorithm: 'HS256',
    },
  );
}

describe('JwtVerifyService', () => {
  const service = new JwtVerifyService(configServiceWith(CFG));

  it('throws when jwt config is missing', () => {
    expect(() => new JwtVerifyService(configServiceWith(undefined))).toThrow(
      'Missing jwt config',
    );
  });

  it('rejects a missing bearer token', () => {
    expect(() => service.verifyBearer(undefined)).toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a header without the Bearer prefix', () => {
    expect(() => service.verifyBearer('Basic abc')).toThrow(
      UnauthorizedException,
    );
  });

  it('verifies a valid access token and maps AuthContext to AuthUser', () => {
    const token = signAccessToken({
      sub: 'user-42',
      roles: ['OWNER', 'ADMIN'],
    });

    const user = service.verifyBearer(`Bearer ${token}`);

    expect(user).toEqual({
      sub: 'user-42',
      tenantId: TENANT,
      roles: ['OWNER', 'ADMIN'],
    });
  });

  it('carries over optional actor/app claims when present', () => {
    const token = signAccessToken({
      actorType: 'service_account',
      clientAppId: 'app-1',
      serviceAccountId: 'svc-1',
    });

    const user = service.verifyBearer(`Bearer ${token}`);

    expect(user).toMatchObject({
      actorType: 'service_account',
      clientAppId: 'app-1',
      serviceAccountId: 'svc-1',
    });
  });

  it('rejects a token signed with the wrong secret', () => {
    const token = signAccessToken({ secret: 'wrong-secret' });
    expect(() => service.verifyBearer(`Bearer ${token}`)).toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a token with the wrong issuer', () => {
    const token = signAccessToken({ issuer: 'http://evil.example' });
    expect(() => service.verifyBearer(`Bearer ${token}`)).toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a token with the wrong audience', () => {
    const token = signAccessToken({ audience: 'some-other-api' });
    expect(() => service.verifyBearer(`Bearer ${token}`)).toThrow(
      UnauthorizedException,
    );
  });

  it('rejects an expired token', () => {
    const token = signAccessToken({ expiresIn: '-1s' });
    expect(() => service.verifyBearer(`Bearer ${token}`)).toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a token missing the tenantId claim', () => {
    const token = jwt.sign(
      { sub: 'user-1', roles: ['MEMBER'], type: 'access' },
      CFG.hs256Secret,
      {
        issuer: CFG.issuer,
        audience: CFG.audience,
        expiresIn: '5m',
        algorithm: 'HS256',
      },
    );

    expect(() => service.verifyBearer(`Bearer ${token}`)).toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a non-access (e.g. refresh) token', () => {
    const token = signAccessToken({ type: 'refresh' });
    expect(() => service.verifyBearer(`Bearer ${token}`)).toThrow(
      UnauthorizedException,
    );
  });
});
