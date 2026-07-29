export type AuthUser = {
  sub: string; // userId
  tenantId: string;
  roles: string[];
  actorType?: 'user' | 'service_account';
  clientAppId?: string;
  serviceAccountId?: string;
};
