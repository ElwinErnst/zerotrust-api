import Anthropic from '@anthropic-ai/sdk';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { PolicyGeneratorConfig } from '../../config/policy-generator.config';
import {
  POLICY_SET_JSON_SCHEMA,
  PolicySet,
  policySetSchema,
} from './schema/policy.schema';

export type GenerateInput = {
  intent: string;
  tenantSlug?: string;
};

export type GenerateResult = {
  policy: PolicySet;
  warnings: string[];
  model: string;
  latencyMs: number;
  tokens: { input: number; output: number };
  costUsd: number;
};

const PRICING: Record<string, { input: number; output: number }> = {
  'claude-sonnet-5': { input: 3, output: 15 },
};

const SYSTEM_PROMPT = `You are a policy compiler for a Zero Trust API gateway.
Given a natural-language intent, emit a JSON policy set that the gateway can evaluate.

Semantics:
- Rules are evaluated top to bottom. The first rule whose "when" AND "if" match is the decision.
- If no rule matches, the policy set's "default" applies.
- "effect": "allow" grants the request; "effect": "deny" blocks it with an optional "reason".

Available upstreams: vault, auth, billing.
HTTP methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS.
Standard human roles: OWNER, ADMIN, MEMBER. You may also use domain roles like EDITOR, VIEWER,
etc. — they are opaque strings the caller's JWT will carry.
"actorTypeIn" distinguishes real users ("user") from API integrations ("service_account").

Rules of thumb:
- Prefer allow-listing over deny-listing: emit specific allow rules and a "default": "deny".
- Keep rule count small — collapse similar rules with method arrays and path globs.
- Each rule's "description" should be a short human phrase (imperative or descriptive), not the
  raw intent verbatim.
- If the intent is ambiguous (e.g. "editors write only their own docs" — the gateway cannot see
  ownership), add a WARNING in your response instead of inventing behavior. Emit the safest
  approximation you can and flag the gap.
- If the intent references an upstream you were not told about, emit a warning and use "vault"
  as a placeholder, not an invented upstream.`;

const RESPONSE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['policy', 'warnings'],
  properties: {
    policy: POLICY_SET_JSON_SCHEMA,
    warnings: {
      // Same Anthropic caveat: maxLength/minLength on items work but
      // maxItems on the array does not. Bounded on the client side.
      type: 'array',
      items: { type: 'string', minLength: 1, maxLength: 400 },
    },
  },
} as const;

@Injectable()
export class PolicyGeneratorService {
  private readonly logger = new Logger(PolicyGeneratorService.name);
  private readonly config: PolicyGeneratorConfig;
  private readonly client: Anthropic | null;

  constructor(private readonly configService: ConfigService) {
    this.config =
      this.configService.get<PolicyGeneratorConfig>('policyGenerator')!;
    this.client =
      this.config.enabled && this.config.apiKey
        ? new Anthropic({
            apiKey: this.config.apiKey,
            timeout: this.config.timeoutMs,
            maxRetries: this.config.maxRetries,
          })
        : null;

    if (this.config.enabled && !this.client) {
      this.logger.warn(
        'Policy generator enabled but ANTHROPIC_API_KEY is missing; generation is disabled.',
      );
    }
  }

  get isEnabled(): boolean {
    return this.client !== null;
  }

  async generate(input: GenerateInput): Promise<GenerateResult> {
    if (!this.client) {
      throw new Error(
        'Policy generator is not configured (disabled or missing API key).',
      );
    }
    if (!input.intent || input.intent.trim().length === 0) {
      throw new Error('intent is required');
    }

    const userContent = JSON.stringify(
      {
        tenant_slug: input.tenantSlug ?? null,
        intent: input.intent.trim(),
      },
      null,
      2,
    );

    const startedAt = Date.now();
    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: this.config.maxTokens,
      thinking: { type: 'disabled' },
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userContent }],
      output_config: {
        format: { type: 'json_schema', schema: RESPONSE_SCHEMA },
      },
    });
    const latencyMs = Date.now() - startedAt;

    const textBlock = response.content.find((b) => b.type === 'text');
    if (!textBlock || textBlock.type !== 'text') {
      throw new Error(
        `Claude returned no text block (stop_reason=${response.stop_reason})`,
      );
    }

    const raw = JSON.parse(textBlock.text) as {
      policy: unknown;
      warnings: string[];
    };

    // Second line of defence: even with structured output, we re-validate
    // with Zod so any drift between the JSON schema and our runtime shape
    // trips here, not deep in the gateway.
    const policy = policySetSchema.parse(raw.policy);

    const pricing = PRICING[response.model] ?? { input: 0, output: 0 };
    const costUsd =
      (response.usage.input_tokens / 1_000_000) * pricing.input +
      (response.usage.output_tokens / 1_000_000) * pricing.output;

    return {
      policy,
      warnings: raw.warnings ?? [],
      model: response.model,
      latencyMs,
      tokens: {
        input: response.usage.input_tokens,
        output: response.usage.output_tokens,
      },
      costUsd,
    };
  }
}
