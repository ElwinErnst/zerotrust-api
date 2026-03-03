import { registerAs } from '@nestjs/config';

export type UpstreamName = 'vault';

export type UpstreamConfig = {
  name: UpstreamName;
  baseUrl: string;
  matchPrefix: string; // ej: "/vault"
};

export default registerAs('upstreams', () => {
  const vaultBaseUrl = process.env.VAULT_BASE_URL ?? 'http://localhost:3000';

  const upstreams: UpstreamConfig[] = [
    { name: 'vault', baseUrl: vaultBaseUrl, matchPrefix: '/vault' },
  ];

  return { upstreams };
});
