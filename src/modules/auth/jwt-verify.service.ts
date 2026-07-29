import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHmac, timingSafeEqual } from 'crypto';
import type { AuthUser } from './types';
import type { JwtConfig } from './types/jwt-config.type';
import type { JwtHeader } from './types/jwt-header.type';
import type { JwtPayload } from './types/jwt-payload.type';

function base64UrlDecodeToBuffer(input: string): Buffer {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return Buffer.from(b64, 'base64');
}

function safeJsonParse<T>(buf: Buffer): T {
  const s = buf.toString('utf8');
  return JSON.parse(s) as T;
}

@Injectable()
export class JwtVerifyService {
  private readonly cfg: JwtConfig;

  constructor(config: ConfigService) {
    const jwt = config.get<JwtConfig>('jwt');
    if (!jwt) throw new Error('Missing jwt config');
    this.cfg = jwt;
  }

  verifyBearer(authHeader: string | undefined): AuthUser {
    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing bearer token');
    }
    const token = authHeader.slice('Bearer '.length).trim();
    return this.verifyHs256(token);
  }

  private verifyHs256(token: string): AuthUser {
    const parts = token.split('.');
    if (parts.length !== 3) throw new UnauthorizedException('Invalid token');

    const [h, p, sig] = parts;

    const header = safeJsonParse<JwtHeader>(base64UrlDecodeToBuffer(h));
    if (header.alg !== 'HS256')
      throw new UnauthorizedException('Unsupported alg');

    const data = `${h}.${p}`;
    const expected = createHmac('sha256', this.cfg.hs256Secret)
      .update(data)
      .digest();

    const actual = base64UrlDecodeToBuffer(sig);
    if (
      expected.length !== actual.length ||
      !timingSafeEqual(expected, actual)
    ) {
      throw new UnauthorizedException('Bad signature');
    }

    const payload = safeJsonParse<JwtPayload>(base64UrlDecodeToBuffer(p));

    if (payload.iss !== this.cfg.issuer)
      throw new UnauthorizedException('Bad issuer');
    if (!this.audienceOk(payload.aud))
      throw new UnauthorizedException('Bad audience');

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) throw new UnauthorizedException('Token expired');

    const tenantId = payload.tenantId;
    const roles = payload.roles ?? [];

    if (!tenantId) throw new UnauthorizedException('Missing tenantId claim');

    return {
      sub: payload.sub,
      tenantId,
      roles,
      ...(payload.actorType == null ? {} : { actorType: payload.actorType }),
      ...(payload.clientAppId == null
        ? {}
        : { clientAppId: payload.clientAppId }),
      ...(payload.serviceAccountId == null
        ? {}
        : { serviceAccountId: payload.serviceAccountId }),
    };
  }

  private audienceOk(aud: JwtPayload['aud']): boolean {
    if (!aud) return false;
    if (typeof aud === 'string') return aud === this.cfg.audience;
    return aud.includes(this.cfg.audience);
  }
}
