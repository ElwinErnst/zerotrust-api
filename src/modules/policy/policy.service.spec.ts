import { PolicyService } from './policy.service';

describe('PolicyService', () => {
  const authDirectory = {
    getTenantEntitlements: jest.fn(),
  };
  const tenantPolicy = {
    resolve: jest.fn(),
  };

  let service: PolicyService;

  beforeEach(() => {
    jest.resetAllMocks();
    // No published PolicySet for the tenant → decisions fall through to the
    // entitlements layer these tests exercise.
    tenantPolicy.resolve.mockResolvedValue({ status: 'none' });
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

    service = new PolicyService(authDirectory as never, tenantPolicy as never);
  });

  it('evaluates the published policy when present (precedence over RBAC)', async () => {
    tenantPolicy.resolve.mockResolvedValueOnce({
      status: 'found',
      version: 4,
      policySet: {
        version: 1,
        rules: [
          {
            description: 'deny all documents',
            effect: 'deny',
            when: { upstream: 'vault', pathGlob: '/documents*' },
            reason: 'blocked by tenant policy',
          },
        ],
        default: 'deny',
      },
    });

    await expect(
      service.decide({
        upstream: 'vault',
        method: 'GET',
        path: '/documents',
        tenantId: 'tenant-1',
        roles: ['ADMIN'],
      }),
    ).resolves.toEqual({ allow: false, reason: 'blocked by tenant policy' });
  });

  it('does not let a policy grant beyond plan entitlements (vaults off)', async () => {
    tenantPolicy.resolve.mockResolvedValueOnce({
      status: 'found',
      version: 1,
      policySet: {
        version: 1,
        rules: [
          {
            description: 'allow everything',
            effect: 'allow',
            when: { upstream: 'vault' },
          },
        ],
        default: 'allow',
      },
    });
    authDirectory.getTenantEntitlements.mockResolvedValueOnce({
      planCode: 'FREE',
      features: {
        vaults: false,
        ztPolicies: true,
        digitalNotary: false,
        auditExport: false,
        customBranding: false,
        sso: false,
        apiAuth: false,
        apiVault: false,
        apiZeroTrust: false,
      },
      limits: {
        maxVaults: 0,
        maxUsers: 5,
        auditRetentionDays: 30,
        monthlyNotaryRequests: 0,
      },
      addonsAllowed: [],
      apiAddons: [],
      source: 'catalog',
    });

    await expect(
      service.decide({
        upstream: 'vault',
        method: 'GET',
        path: '/documents',
        tenantId: 'tenant-1',
        roles: ['ADMIN'],
      }),
    ).resolves.toEqual({
      allow: false,
      reason: 'Vault access is not enabled for this tenant plan',
    });
  });

  it('ignores a published policy when the plan lacks ztPolicies (RBAC applies)', async () => {
    tenantPolicy.resolve.mockResolvedValueOnce({
      status: 'found',
      version: 1,
      policySet: {
        version: 1,
        rules: [
          {
            description: 'deny all',
            effect: 'deny',
            when: { upstream: 'vault' },
            reason: 'policy would block',
          },
        ],
        default: 'deny',
      },
    });
    authDirectory.getTenantEntitlements.mockResolvedValueOnce({
      planCode: 'BUSINESS',
      features: {
        vaults: true,
        ztPolicies: false,
        digitalNotary: false,
        auditExport: false,
        customBranding: false,
        sso: false,
        apiAuth: true,
        apiVault: true,
        apiZeroTrust: false,
      },
      limits: {
        maxVaults: 30,
        maxUsers: 100,
        auditRetentionDays: 365,
        monthlyNotaryRequests: 0,
      },
      addonsAllowed: ['VAULT_API'],
      apiAddons: ['VAULT_API'],
      source: 'catalog',
    });

    // Policy would deny, but ztPolicies is off → RBAC lets an ADMIN GET through.
    await expect(
      service.decide({
        upstream: 'vault',
        method: 'GET',
        path: '/documents',
        tenantId: 'tenant-1',
        roles: ['ADMIN'],
      }),
    ).resolves.toEqual({ allow: true });
  });

  it('fails closed (deny) when the policy service is unavailable', async () => {
    tenantPolicy.resolve.mockResolvedValueOnce({ status: 'error' });

    await expect(
      service.decide({
        upstream: 'vault',
        method: 'GET',
        path: '/documents',
        tenantId: 'tenant-1',
        roles: ['ADMIN'],
      }),
    ).resolves.toEqual({ allow: false, reason: 'Policy service unavailable' });
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
