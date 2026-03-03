import { z } from 'zod';

export const PolicyRuleSchema = z.object({
  upstream: z.string().min(1),
  method: z.string().min(1), // 'GET' | 'POST' etc (lo validamos en service)
  path: z.string().min(1), // '/documents' (se puede usar prefix match)
  allowRoles: z.array(z.string().min(1)).default([]), // ej ['ADMIN','MEMBER']
});

export const PoliciesFileSchema = z.object({
  version: z.number().int().positive().default(1),
  rules: z.array(PolicyRuleSchema).default([]),
});

export type PoliciesFile = z.infer<typeof PoliciesFileSchema>;

export const UpstreamSchema = z.object({
  name: z.string().min(1),
  baseUrl: z.string().url(),
  matchPrefix: z.string().min(1), // ej '/apps/vault'
});

export const UpstreamsFileSchema = z.object({
  version: z.number().int().positive().default(1),
  upstreams: z.array(UpstreamSchema).default([]),
});

export type UpstreamsFile = z.infer<typeof UpstreamsFileSchema>;
