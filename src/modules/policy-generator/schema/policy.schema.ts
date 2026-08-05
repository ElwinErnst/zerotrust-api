import { z } from 'zod';

// The gateway currently only proxies /vault; upstreams are pinned to the
// values the ZT gateway actually knows. Extending this list requires wiring
// a matching upstream module in gateway.module.ts.
export const UPSTREAM_VALUES = ['vault', 'auth', 'billing'] as const;
export const HTTP_METHOD_VALUES = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
] as const;
export const HUMAN_ROLE_VALUES = ['OWNER', 'ADMIN', 'MEMBER'] as const;
export const ACTOR_TYPE_VALUES = ['user', 'service_account'] as const;

export const policyWhenSchema = z
  .object({
    upstream: z.enum(UPSTREAM_VALUES),
    methods: z.array(z.enum(HTTP_METHOD_VALUES)).nonempty().optional(),
    pathGlob: z.string().min(1).optional(),
  })
  .strict();

export const policyIfSchema = z
  .object({
    roleIn: z.array(z.string().min(1)).nonempty().optional(),
    actorTypeIn: z.array(z.enum(ACTOR_TYPE_VALUES)).nonempty().optional(),
  })
  .strict();

export const policyRuleSchema = z
  .object({
    description: z.string().min(1).max(200),
    effect: z.enum(['allow', 'deny']),
    when: policyWhenSchema,
    if: policyIfSchema.optional(),
    reason: z.string().max(200).optional(),
  })
  .strict();

export const policySetSchema = z
  .object({
    version: z.literal(1),
    rules: z.array(policyRuleSchema).max(50),
    default: z.enum(['allow', 'deny']),
  })
  .strict();

export type PolicyWhen = z.infer<typeof policyWhenSchema>;
export type PolicyIf = z.infer<typeof policyIfSchema>;
export type PolicyRule = z.infer<typeof policyRuleSchema>;
export type PolicySet = z.infer<typeof policySetSchema>;

// JSON Schema shape mirrored explicitly for Claude's structured output.
// Kept in this file so a Zod change without a JSON Schema change trips a
// PR review — the two representations MUST stay in sync.
export const POLICY_SET_JSON_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['version', 'rules', 'default'],
  properties: {
    version: { type: 'integer', const: 1 },
    rules: {
      // NOTE: Anthropic's structured-output validator rejects `maxItems` on
      // arrays with an "invalid_request_error". The 50-rule cap is enforced
      // by the Zod schema at runtime instead — the model gets a hint via
      // SYSTEM_PROMPT ("keep rule count small").
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['description', 'effect', 'when'],
        properties: {
          description: { type: 'string', minLength: 1, maxLength: 200 },
          effect: { type: 'string', enum: ['allow', 'deny'] },
          when: {
            type: 'object',
            additionalProperties: false,
            required: ['upstream'],
            properties: {
              upstream: { type: 'string', enum: [...UPSTREAM_VALUES] },
              methods: {
                // minItems similarly not supported by Anthropic's validator;
                // enforced by Zod at runtime.
                type: 'array',
                items: { type: 'string', enum: [...HTTP_METHOD_VALUES] },
              },
              pathGlob: { type: 'string', minLength: 1 },
            },
          },
          if: {
            type: 'object',
            additionalProperties: false,
            properties: {
              roleIn: {
                type: 'array',
                items: { type: 'string', minLength: 1 },
              },
              actorTypeIn: {
                type: 'array',
                items: { type: 'string', enum: [...ACTOR_TYPE_VALUES] },
              },
            },
          },
          reason: { type: 'string', maxLength: 200 },
        },
      },
    },
    default: { type: 'string', enum: ['allow', 'deny'] },
  },
} as const;
