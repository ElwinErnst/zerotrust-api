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
  // Outbound signing mode for the gateway->Vault hop. Defaults to the legacy
  // HMAC so this ships dormant; flip to 'ed25519' via env once Vault trusts the
  // public key. Reversible with no Vault redeploy.
  signMode:
    (process.env.ZT_SIGN_MODE ?? 'hmac') === 'ed25519' ? 'ed25519' : 'hmac',
  // Key id advertised in x-zt-kid; must match an entry in Vault's keyring.
  signingKid: process.env.ZT_SIGNING_KID ?? '',
  // Ed25519 private key (PEM, or base64-encoded PEM). Secret — never logged or
  // returned. Only required when signMode is 'ed25519'.
  signingPrivateKey: process.env.ZT_SIGNING_PRIVATE_KEY ?? '',
  // Decision-log retention: rows older than this are purged periodically so the
  // high-volume audit_events table stays bounded. 0 disables purging.
  auditRetentionDays: Math.max(
    0,
    Math.floor(Number(process.env.ZT_AUDIT_RETENTION_DAYS ?? 90)) || 0,
  ),
}));
