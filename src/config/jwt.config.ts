import { registerAs } from '@nestjs/config';

function readSecret(envName: string, fallback: string) {
  const value = process.env[envName]?.trim();
  if (value) return value;

  const runtime = process.env.NODE_ENV ?? 'development';
  if (runtime === 'development' || runtime === 'test') {
    return fallback;
  }

  throw new Error(`${envName} must be configured outside development/test`);
}

export default registerAs('jwt', () => ({
  issuer: process.env.ZT_JWT_ISSUER ?? 'http://localhost:3000',
  audience: process.env.ZT_JWT_AUDIENCE ?? 'vault-api',
  hs256Secret: readSecret('ZT_JWT_HS256_SECRET', 'dev-secret-change-me'),
}));
