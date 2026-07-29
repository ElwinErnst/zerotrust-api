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

export default registerAs('billingMetering', () => ({
  baseUrl: process.env.BILLING_METERING_BASE_URL ?? '',
  serviceSecret: readSecret(
    'BILLING_INTERNAL_SERVICE_SECRET',
    'change-me-billing-internal-secret',
  ),
  hmacSecret: readSecret(
    'BILLING_INTERNAL_HMAC_SECRET',
    'change-me-billing-internal-hmac-secret',
  ),
  timeoutMs: Number(process.env.BILLING_METERING_TIMEOUT_MS ?? 5000),
}));
