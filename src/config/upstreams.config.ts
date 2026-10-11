import { registerAs } from '@nestjs/config';

// The built-in, operator-trusted upstream. Kept as a named constant so that
// vault-specific behavior (feature ceilings, metering, RBAC routes) can still
// key off it while the gateway becomes generic over arbitrary registered
// upstreams.
export const VAULT_UPSTREAM_NAME = 'vault';

// Was a single literal ('vault'); now any registered upstream name. Non-vault
// upstreams come from the file registry (AdminService / ZT_UPSTREAMS_FILE).
export type UpstreamName = string;

export type UpstreamConfig = {
  name: UpstreamName;
  baseUrl: string;
  matchPrefix: string; // "/vault" (built-in) or "/gw/<name>" (registered)
};

export default registerAs('upstreams', () => {
  const vaultBaseUrl = process.env.VAULT_BASE_URL ?? 'http://localhost:3000';

  const upstreams: UpstreamConfig[] = [
    { name: VAULT_UPSTREAM_NAME, baseUrl: vaultBaseUrl, matchPrefix: '/vault' },
  ];

  return { upstreams };
});
