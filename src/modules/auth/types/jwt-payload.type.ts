export type JwtPayload = {
  sub: string;
  iss: string;
  aud?: string | string[];
  exp: number;
  tenantId?: string;
  roles?: string[];
  actorType?: 'user' | 'service_account';
  clientAppId?: string;
  serviceAccountId?: string;
};
