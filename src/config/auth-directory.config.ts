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

export default registerAs('authDirectory', () => ({
  baseUrl: process.env.AUTH_DIRECTORY_BASE_URL ?? 'http://localhost:3001/api',
  serviceSecret: readSecret(
    'AUTH_DIRECTORY_SERVICE_SECRET',
    'change-me-internal-secret',
  ),
  hmacSecret: readSecret(
    'AUTH_DIRECTORY_HMAC_SECRET',
    'change-me-internal-hmac-secret',
  ),
  timeoutMs: Number(process.env.AUTH_DIRECTORY_TIMEOUT_MS ?? 5000),
}));
