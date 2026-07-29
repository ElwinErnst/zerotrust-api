export type UsageEventPayload = {
  tenantId: string;
  addonCode: 'AUTH_API' | 'VAULT_API' | 'ZERO_TRUST_API';
  metric: string;
  quantity: number;
  sourceService: string;
  actorType?: string;
  clientAppId?: string;
  serviceAccountId?: string;
  metadata?: Record<string, unknown>;
};
