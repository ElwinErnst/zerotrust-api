import {
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, createHmac, randomUUID } from 'crypto';

type AuthDirectoryConfig = {
  baseUrl: string;
  serviceSecret: string;
  hmacSecret: string;
  timeoutMs: number;
};

export type RemoteTenantEntitlements = {
  planCode: string;
  features: {
    vaults: boolean;
    ztPolicies: boolean;
    digitalNotary: boolean;
    auditExport: boolean;
    customBranding: boolean;
    sso: boolean;
    apiAuth: boolean;
    apiVault: boolean;
    apiZeroTrust: boolean;
  };
  limits: {
    maxVaults: number | null;
    maxUsers: number | null;
    auditRetentionDays: number | null;
    monthlyNotaryRequests: number | null;
  };
  addonsAllowed: string[];
  apiAddons: Array<'AUTH_API' | 'VAULT_API' | 'ZERO_TRUST_API'>;
  source:
    | 'catalog'
    | 'catalog_with_legacy_overrides'
    | 'legacy_defaults'
    | 'billing_bypass';
};

export type RemoteTenantPolicy = {
  policySet: unknown; // schema owned/validated by zerotrust-api
  version: number;
};

@Injectable()
export class AuthDirectoryService {
  private readonly cfg: AuthDirectoryConfig;

  constructor(private readonly config: ConfigService) {
    this.cfg = this.config.get<AuthDirectoryConfig>('authDirectory')!;
  }

  async getTenantEntitlements(
    tenantId: string,
  ): Promise<RemoteTenantEntitlements | null> {
    const url = this.buildUrl(`internal/tenants/${tenantId}/entitlements`);
    return this.fetchJson<RemoteTenantEntitlements>(url.toString(), {
      allow404: true,
    });
  }

  /**
   * The tenant's currently published Zero Trust policy, or null when the tenant
   * has none (auth-api returns 404). Any other failure throws — the caller must
   * fail closed rather than treat an unreachable auth-api as "no policy".
   */
  async getTenantPolicy(tenantId: string): Promise<RemoteTenantPolicy | null> {
    const url = this.buildUrl(`internal/tenants/${tenantId}/policy`);
    return this.fetchJson<RemoteTenantPolicy>(url.toString(), {
      allow404: true,
    });
  }

  private buildUrl(path: string): URL {
    const base = this.cfg.baseUrl.endsWith('/')
      ? this.cfg.baseUrl
      : `${this.cfg.baseUrl}/`;

    return new URL(path, base);
  }

  private buildSignedHeaders(
    method: string,
    url: URL,
    body?: string,
  ): Record<string, string> {
    const normalizedBody = body ?? '{}';
    const ts = String(Date.now());
    const nonce = randomUUID();
    const bodySha256Hex = createHash('sha256')
      .update(normalizedBody)
      .digest('hex');
    const canonical = [
      method.toUpperCase(),
      `${url.pathname}${url.search}`,
      bodySha256Hex,
      ts,
      nonce,
    ].join('\n');
    const signature = createHmac('sha256', this.cfg.hmacSecret)
      .update(canonical)
      .digest('hex');

    return {
      'x-internal-service-secret': this.cfg.serviceSecret,
      'x-internal-service-ts': ts,
      'x-internal-service-nonce': nonce,
      'x-internal-service-signature': signature,
    };
  }

  private async fetchJson<T>(
    url: string,
    options?: { allow404?: boolean },
  ): Promise<T | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.cfg.timeoutMs);
    const parsedUrl = new URL(url);
    const headers = this.buildSignedHeaders('GET', parsedUrl);

    try {
      const res = await fetch(url, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });

      if (options?.allow404 && res.status === 404) {
        return null;
      }

      if (res.status === 404) {
        throw new NotFoundException('Auth directory resource not found');
      }

      if (res.status === 403) {
        throw new ForbiddenException('Auth directory rejected service request');
      }

      if (!res.ok) {
        throw new InternalServerErrorException(
          `Auth directory request failed with status ${res.status}`,
        );
      }

      return (await res.json()) as T;
    } catch (error) {
      if (
        error instanceof NotFoundException ||
        error instanceof ForbiddenException ||
        error instanceof InternalServerErrorException
      ) {
        throw error;
      }

      throw new InternalServerErrorException('Auth directory request failed');
    } finally {
      clearTimeout(timeout);
    }
  }
}
