import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { verifyBearer as verifyBearerStandalone } from '@elwinernst/nest-auth/standalone';
import type { AuthUser } from './types';
import type { JwtConfig } from './types/jwt-config.type';

@Injectable()
export class JwtVerifyService {
  private readonly cfg: JwtConfig;

  constructor(config: ConfigService) {
    const jwt = config.get<JwtConfig>('jwt');
    if (!jwt) throw new Error('Missing jwt config');
    this.cfg = jwt;
  }

  verifyBearer(authHeader: string | undefined): AuthUser {
    const ctx = verifyBearerStandalone(authHeader, {
      issuer: this.cfg.issuer,
      audience: this.cfg.audience,
      secret: this.cfg.hs256Secret,
    });

    return {
      sub: ctx.userId,
      tenantId: ctx.tenantId,
      roles: ctx.roles,
      ...(ctx.actorType == null ? {} : { actorType: ctx.actorType }),
      ...(ctx.clientAppId == null ? {} : { clientAppId: ctx.clientAppId }),
      ...(ctx.serviceAccountId == null
        ? {}
        : { serviceAccountId: ctx.serviceAccountId }),
    };
  }
}
