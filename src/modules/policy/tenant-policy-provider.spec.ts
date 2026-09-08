import { Test } from '@nestjs/testing';
import { AuthDirectoryService } from '../../common/modules/auth-directory/auth-directory.service';
import { TenantPolicyProvider } from './tenant-policy-provider';

const TENANT = 'tenant-1';

const validPolicySet = {
  version: 1,
  rules: [
    {
      description: 'allow vault reads',
      effect: 'allow',
      when: { upstream: 'vault', methods: ['GET'], pathGlob: '/documents*' },
    },
  ],
  default: 'deny',
};

function providerWith(getTenantPolicy: jest.Mock): {
  provider: TenantPolicyProvider;
  getTenantPolicy: jest.Mock;
} {
  const authDirectory = { getTenantPolicy } as unknown as AuthDirectoryService;
  return {
    provider: new TenantPolicyProvider(authDirectory),
    getTenantPolicy,
  };
}

describe('TenantPolicyProvider', () => {
  it('returns found with the validated policy set', async () => {
    const { provider } = providerWith(
      jest.fn().mockResolvedValue({ policySet: validPolicySet, version: 3 }),
    );
    const res = await provider.resolve(TENANT);
    expect(res).toEqual({
      status: 'found',
      policySet: validPolicySet,
      version: 3,
    });
  });

  it('returns none when auth-api has no policy (404 -> null)', async () => {
    const { provider } = providerWith(jest.fn().mockResolvedValue(null));
    await expect(provider.resolve(TENANT)).resolves.toEqual({ status: 'none' });
  });

  it('returns error (fail-safe) when auth-api is unreachable', async () => {
    const { provider } = providerWith(
      jest.fn().mockRejectedValue(new Error('ECONNREFUSED')),
    );
    await expect(provider.resolve(TENANT)).resolves.toEqual({
      status: 'error',
    });
  });

  it('returns error when the stored policy fails schema validation', async () => {
    const { provider } = providerWith(
      jest.fn().mockResolvedValue({
        policySet: { version: 1, rules: [], default: 'maybe' },
        version: 1,
      }),
    );
    await expect(provider.resolve(TENANT)).resolves.toEqual({
      status: 'error',
    });
  });

  it('caches a successful resolution within the TTL (single fetch)', async () => {
    const { provider, getTenantPolicy } = providerWith(
      jest.fn().mockResolvedValue({ policySet: validPolicySet, version: 1 }),
    );
    await provider.resolve(TENANT);
    await provider.resolve(TENANT);
    expect(getTenantPolicy).toHaveBeenCalledTimes(1);
  });

  it('does not cache errors (retries on next call)', async () => {
    const getTenantPolicy = jest
      .fn()
      .mockRejectedValueOnce(new Error('down'))
      .mockResolvedValueOnce({ policySet: validPolicySet, version: 1 });
    const { provider } = providerWith(getTenantPolicy);

    await expect(provider.resolve(TENANT)).resolves.toEqual({
      status: 'error',
    });
    await expect(provider.resolve(TENANT)).resolves.toMatchObject({
      status: 'found',
    });
    expect(getTenantPolicy).toHaveBeenCalledTimes(2);
  });
});

describe('TenantPolicyProvider DI', () => {
  it('resolves via Nest with only AuthDirectoryService (no primitive ctor arg)', async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        TenantPolicyProvider,
        {
          provide: AuthDirectoryService,
          useValue: { getTenantPolicy: jest.fn() },
        },
      ],
    }).compile();

    expect(moduleRef.get(TenantPolicyProvider)).toBeInstanceOf(
      TenantPolicyProvider,
    );
  });
});
