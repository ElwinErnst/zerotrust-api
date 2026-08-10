const create = jest.fn();

jest.mock('@anthropic-ai/sdk', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => ({ messages: { create } })),
}));

import { ConfigService } from '@nestjs/config';

import { PolicyGeneratorService } from './policy-generator.service';
import type { PolicyGeneratorConfig } from '../../config/policy-generator.config';
import type { PolicySet } from './schema/policy.schema';

const VALID_POLICY: PolicySet = {
  version: 1,
  default: 'deny',
  rules: [
    {
      description: 'Allow ADMIN to manage documents',
      effect: 'allow',
      when: { upstream: 'vault', pathGlob: '/documents/**' },
      if: { roleIn: ['ADMIN'] },
    },
  ],
};

function makeService(
  over: Partial<PolicyGeneratorConfig> = {},
): PolicyGeneratorService {
  const config: PolicyGeneratorConfig = {
    enabled: true,
    apiKey: 'sk-ant-test',
    model: 'claude-sonnet-5',
    maxTokens: 2048,
    timeoutMs: 20000,
    maxRetries: 1,
    ...over,
  };
  const configService = {
    get: jest.fn().mockReturnValue(config),
  } as unknown as ConfigService;
  return new PolicyGeneratorService(configService);
}

function grantedResponse(policy: unknown, warnings: string[] = []) {
  return {
    model: 'claude-sonnet-5',
    stop_reason: 'end_turn',
    content: [{ type: 'text', text: JSON.stringify({ policy, warnings }) }],
    usage: { input_tokens: 1200, output_tokens: 240 },
  };
}

describe('PolicyGeneratorService', () => {
  beforeEach(() => create.mockReset());

  it('is disabled (and throws) when no API key is configured', async () => {
    const service = makeService({ apiKey: null });
    expect(service.isEnabled).toBe(false);
    await expect(service.generate({ intent: 'anything' })).rejects.toThrow(
      /not configured/i,
    );
    expect(create).not.toHaveBeenCalled();
  });

  it('rejects an empty intent without calling the model', async () => {
    const service = makeService();
    await expect(service.generate({ intent: '   ' })).rejects.toThrow(
      /intent is required/i,
    );
    expect(create).not.toHaveBeenCalled();
  });

  it('compiles an intent into a validated PolicySet with cost accounting', async () => {
    create.mockResolvedValue(
      grantedResponse(VALID_POLICY, ['ownership not visible']),
    );
    const service = makeService();

    const result = await service.generate({
      intent: 'admins manage documents',
      tenantSlug: 'acme',
    });

    expect(result.policy).toEqual(VALID_POLICY);
    expect(result.warnings).toEqual(['ownership not visible']);
    expect(result.tokens).toEqual({ input: 1200, output: 240 });
    // 1200/1e6*3 + 240/1e6*15 = 0.0036 + 0.0036 = 0.0072
    expect(result.costUsd).toBeCloseTo(0.0072, 6);
  });

  it('rejects model output that fails schema re-validation', async () => {
    // effect must be allow|deny; the Zod re-validation is the second line of defence.
    create.mockResolvedValue(
      grantedResponse({
        version: 1,
        default: 'deny',
        rules: [{ description: 'bad', effect: 'maybe', when: {}, if: {} }],
      }),
    );
    const service = makeService();

    await expect(service.generate({ intent: 'something' })).rejects.toThrow();
  });
});
