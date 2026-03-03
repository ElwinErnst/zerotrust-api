import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { verifyZtRequest } from './zt-verify';

type ZtCfg = {
  hmacSecret: string;
  maxClockSkewMs?: number;
};

@Injectable()
export class ZtGuard implements CanActivate {
  private readonly secret: string;
  private readonly maxSkewMs: number;

  // simple anti-replay en memoria (MVP)
  private readonly replayCache = new Map<string, number>();

  constructor(cfg: ConfigService) {
    const zt = cfg.get<ZtCfg>('zt');
    if (!zt) throw new Error('Missing zt config');

    this.secret = zt.hmacSecret;
    this.maxSkewMs = zt.maxClockSkewMs ?? 30_000;
  }

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();

    const originalUrl = req.originalUrl ?? req.url ?? '/';
    const [path, queryPart] = originalUrl.split('?');
    const query = queryPart ?? '';

    const result = verifyZtRequest({
      secret: this.secret,
      method: req.method,
      path: path ?? '/',
      query,
      headers: req.headers,
      maxSkewMs: this.maxSkewMs,
      replayCache: this.replayCache,
    });

    if (!result.ok) {
      throw new ForbiddenException(`ZT: ${result.reason}`);
    }

    // attach identity to request
    (req as Request & { zt?: unknown }).zt = {
      userId: result.userId,
      tenantId: result.tenantId,
      roles: result.roles,
    };

    return true;
  }
}
