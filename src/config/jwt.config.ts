import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => ({
  issuer: process.env.ZT_JWT_ISSUER ?? 'http://localhost:3000',
  audience: process.env.ZT_JWT_AUDIENCE ?? 'vault-api',
  hs256Secret: process.env.ZT_JWT_HS256_SECRET ?? 'dev-secret-change-me',
}));
