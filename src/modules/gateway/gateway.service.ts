import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import { UpstreamConfig } from '../../config/upstreams.config';
import { ResolvedUpstream } from './types';

type UpstreamsCfg = { upstreams: UpstreamConfig[] };

@Injectable()
export class GatewayService {
  private readonly upstreams: UpstreamConfig[];

  constructor(cfg: ConfigService) {
    const c = cfg.get<UpstreamsCfg>('upstreams');
    if (!c) throw new Error('Missing upstreams config');
    this.upstreams = c.upstreams;
  }

  resolve(req: Request): ResolvedUpstream | null {
    const url = req.originalUrl || req.url; // includes query
    const path = url.split('?')[0] ?? '/';

    for (const u of this.upstreams) {
      if (path === u.matchPrefix || path.startsWith(`${u.matchPrefix}/`)) {
        const upstreamPath = path.slice(u.matchPrefix.length) || '/';
        return { upstream: u, upstreamPath };
      }
    }

    return null;
  }
}
