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

export default registerAs('zt', () => ({
  hmacSecret: readSecret('ZT_HMAC_SECRET', 'zt-hmac-secret-change-me'),
}));
