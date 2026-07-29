import { PolicyService } from './policy.service';

describe('PolicyService', () => {
  const authDirectory = {
    getTenantEntitlements: jest.fn(),
  };

  let service: PolicyService;

  beforeEach(() => {
    jest.resetAllMocks();
    authDirectory.getTenantEntitlements.mockResolvedValue({
      planCode: 'BUSINESS',
      features: {
        vaults: true,
        ztPolicies: true,
        digitalNotary: false,
        auditExport: false,
        customBranding: false,
        sso: false,
        apiAuth: true,
        apiVault: true,
        apiZeroTrust: true,
      },
      limits: {
        maxVaults: 30,
        maxUsers: 100,
        auditRetentionDays: 365,
        monthlyNotaryRequests: 750,
      },
      addonsAllowed: ['AUTH_API', 'VAULT_API', 'ZERO_TRUST_API'],
      apiAddons: ['AUTH_API', 'VAULT_API', 'ZERO_TRUST_API'],
      source: 'catalog',
    });

    service = new PolicyService(authDirectory as never);
  });

  it('allows API clients to list vaults', async () => {
    await expect(
      service.decide({
        upstream: 'vault',
        method: 'GET',
        path: '/vaults',
        tenantId: 'tenant-1',
        roles: ['API_CLIENT'],
      }),
    ).resolves.toEqual({ allow: true });
  });

  it('denies API clients on administrative vault routes', async () => {
    await expect(
      service.decide({
        upstream: 'vault',
        method: 'DELETE',
        path: '/vaults/abc',
        tenantId: 'tenant-1',
        roles: ['API_CLIENT'],
      }),
    ).resolves.toEqual({
      allow: false,
      reason: 'API client is not allowed on this Vault route',
    });
  });

  it('denies API clients when Vault API pack is missing', async () => {
    authDirectory.getTenantEntitlements.mockResolvedValueOnce({
      planCode: 'BUSINESS',
      features: {
        vaults: true,
        ztPolicies: true,
        digitalNotary: false,
        auditExport: false,
        customBranding: false,
        sso: false,
        apiAuth: true,
        apiVault: false,
        apiZeroTrust: false,
      },
      limits: {
        maxVaults: 30,
        maxUsers: 100,
        auditRetentionDays: 365,
        monthlyNotaryRequests: 750,
      },
      addonsAllowed: ['AUTH_API'],
      apiAddons: ['AUTH_API'],
      source: 'catalog',
    });

    await expect(
      service.decide({
        upstream: 'vault',
        method: 'GET',
        path: '/vaults',
        tenantId: 'tenant-1',
        roles: ['API_CLIENT'],
      }),
    ).resolves.toEqual({
      allow: false,
      reason: 'Vault API Pack is not enabled for this tenant',
    });
  });

  it('keeps human RBAC behavior for workspace users', async () => {
    await expect(
      service.decide({
        upstream: 'vault',
        method: 'DELETE',
        path: '/documents/abc',
        tenantId: 'tenant-1',
        roles: ['MEMBER'],
      }),
    ).resolves.toEqual({
      allow: false,
      reason: 'Missing role ADMIN',
    });
  });
});
