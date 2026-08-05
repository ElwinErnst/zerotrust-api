import { registerAs } from '@nestjs/config';

export type PolicyGeneratorConfig = {
  enabled: boolean;
  apiKey: string | null;
  model: string;
  maxTokens: number;
  timeoutMs: number;
  maxRetries: number;
};

export default registerAs<PolicyGeneratorConfig>('policyGenerator', () => ({
  enabled: (process.env.POLICY_GENERATOR_ENABLED ?? 'false') === 'true',
  apiKey: process.env.ANTHROPIC_API_KEY ?? null,
  model: process.env.POLICY_GENERATOR_MODEL ?? 'claude-sonnet-5',
  maxTokens: Number(process.env.POLICY_GENERATOR_MAX_TOKENS ?? 2048),
  timeoutMs: Number(process.env.POLICY_GENERATOR_TIMEOUT_MS ?? 20000),
  maxRetries: Number(process.env.POLICY_GENERATOR_MAX_RETRIES ?? 1),
}));
