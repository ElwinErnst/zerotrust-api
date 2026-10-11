import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import type { UpstreamConfig } from '../../config/upstreams.config';
import { VAULT_UPSTREAM_NAME } from '../../config/upstreams.config';
import { AdminService } from '../admin/admin.service';
import type { ResolvedUpstream } from './types';
import type { UpstreamsConfig } from './types/upstreams-config.type';

// Registered (non-built-in) upstreams must live under this reserved namespace so
// the untrusted file registry can never shadow the built-in vault route or other
// platform endpoints (/admin, /api/zt, /health).
const REGISTERED_PREFIX = '/gw/';

@Injectable()
export class GatewayService {
  private readonly logger = new Logger(GatewayService.name);
  private readonly builtinUpstreams: UpstreamConfig[];

  constructor(
    cfg: ConfigService,
    private readonly admin: AdminService,
  ) {
    const c = cfg.get<UpstreamsConfig>('upstreams');
    if (!c) throw new Error('Missing upstreams config');
    this.builtinUpstreams = c.upstreams;
  }

  isBuiltin(name: string): boolean {
    return this.builtinUpstreams.some((u) => u.name === name);
  }

  resolve(req: Request): ResolvedUpstream | null {
    const url = req.originalUrl || req.url; // includes query
    const path = url.split('?')[0] ?? '/';

    for (const u of this.allUpstreams()) {
      if (path === u.matchPrefix || path.startsWith(`${u.matchPrefix}/`)) {
        const upstreamPath = path.slice(u.matchPrefix.length) || '/';
        return { upstream: u, upstreamPath };
      }
    }

    return null;
  }

  /**
   * Built-in (operator-trusted) upstreams first, then file-registered ones.
   * A failure reading the untrusted file registry must never break resolution
   * of the built-in vault route, so it is isolated and falls back to built-ins.
   */
  private allUpstreams(): UpstreamConfig[] {
    let registered: UpstreamConfig[] = [];
    try {
      registered = this.admin
        .getUpstreams()
        .upstreams.filter((u) => this.isRegisterable(u));
    } catch (err) {
      this.logger.error(
        `Failed to read upstream registry; serving built-in upstreams only: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    return [...this.builtinUpstreams, ...registered];
  }

  // A file-registered upstream may only claim a prefix inside the reserved
  // namespace, and may not reuse a built-in name. This keeps the untrusted file
  // registry from hijacking vault or platform routes.
  private isRegisterable(u: UpstreamConfig): boolean {
    if (this.isBuiltin(u.name)) {
      this.logger.warn(
        `Ignoring registered upstream reusing built-in name "${u.name}"`,
      );
      return false;
    }
    if (!u.matchPrefix.startsWith(REGISTERED_PREFIX)) {
      this.logger.warn(
        `Ignoring registered upstream "${u.name}": matchPrefix must start with ${REGISTERED_PREFIX}`,
      );
      return false;
    }
    return true;
  }
}
