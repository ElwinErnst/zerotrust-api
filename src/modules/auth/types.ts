export type AuthUser = {
  sub: string; // userId
  tenantId: string;
  roles: string[];
};
