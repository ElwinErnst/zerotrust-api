import { PolicyService } from './policy.service';
import type { PolicyInput } from './types';

// Covers the generic (non-vault) upstream path added for the multi-upstream slice:
// vault feature ceilings/RBAC must NOT apply, a published policy decides, and the
// coarse default requires a human role.
describe('PolicyService — generic (non-vault) upstream', () => {
  const authDirectory = { getTenantEntitlements: jest.fn() };
  const tenantPolicy = { resolve: jest.fn() };
  let service: PolicyService;

  const entitlements = (overrides: Record<string, boolean> = {}) => ({
    planCode: 'BUSINESS',
    features: {
      vaults: false, // deliberately off — must not affect a non-vault upstream
      ztPolicies: true,
      digitalNotary: false,
      auditExport: false,
      customBranding: false,
      sso: false,
      apiAuth: true,
      apiVault: false,
      apiZeroTrust: true,
      ...overrides,
    },
    limits: {},
    addonsAllowed: [],
    apiAddons: [],
    source: 'catalog',
  });

  const input = (over: Partial<PolicyInput> = {}): PolicyInput => ({
    upstream: 'myapp',
    method: 'GET',
    path: '/orders',
    tenantId: 'tenant-1',
    roles: ['MEMBER'],
    actorType: 'user',
    ...over,
  });

  beforeEach(() => {
    jest.resetAllMocks();
    tenantPolicy.resolve.mockResolvedValue({ status: 'none' });
    authDirectory.getTenantEntitlements.mockResolvedValue(entitlements());
    service = new PolicyService(authDirectory as never, tenantPolicy as never);
  });

  it('allows a human MEMBER by coarse default even when vault features are off', async () => {
    await expect(service.decide(input({ roles: ['MEMBER'] }))).resolves.toEqual({
      allow: true,
    });
  });

  it('denies an API client with no published policy (coarse default requires a human role)', async () => {
    const decision = await service.decide(input({ roles: ['API_CLIENT'] }));
    expect(decision.allow).toBe(false);
  });

  it('lets a published PolicySet decide for the registered upstream', async () => {
    tenantPolicy.resolve.mockResolvedValue({
      status: 'found',
      version: 2,
      policySet: {
        version: 1,
        rules: [
          {
            description: 'allow members to read orders',
            effect: 'allow',
            when: { upstream: 'myapp', methods: ['GET'], pathGlob: '/orders*' },
            if: { roleIn: ['MEMBER'] },
          },
        ],
        default: 'deny',
      },
    });

    await expect(service.decide(input())).resolves.toEqual({ allow: true });

    // A path not covered by the rule falls to the policy default (deny).
    const denied = await service.decide(input({ path: '/secret' }));
    expect(denied.allow).toBe(false);
  });

  it('still fails closed when the policy service errors', async () => {
    tenantPolicy.resolve.mockResolvedValue({ status: 'error' });
    const decision = await service.decide(input());
    expect(decision.allow).toBe(false);
  });
});
