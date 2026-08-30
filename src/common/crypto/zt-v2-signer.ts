import { createHash, createPrivateKey, type KeyObject } from 'crypto';
import { randomUUID } from 'crypto';
import { canonicalizeZtV2 } from './canonical';
import { signEd25519 } from './ed25519';
import { signZtRequest } from './hmac-signer';

export type ZtSignedHeadersV2 = {
  'x-zt-v': '2';
  'x-zt-alg': 'ed25519';
  'x-zt-kid': string;
  'x-zt-user-id': string;
  'x-zt-tenant-id': string;
  'x-zt-roles': string;
  'x-zt-ts': string;
  'x-zt-nonce': string;
  'x-zt-body-sha256': string;
  'x-zt-sig': string; // base64
};

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function normalizeRoles(roles: readonly string[]): string {
  return [...roles]
    .map((r) => r.trim().toUpperCase())
    .filter(Boolean)
    .sort()
    .join(',');
}

export type ZtSignRequest = {
  method: string;
  path: string; // without query
  query: string; // without '?'
  body: Buffer; // Buffer.alloc(0) when there is none
  userId: string;
  tenantId: string;
  roles: readonly string[];
  tsMs?: number;
  nonce?: string;
};

/** Sign a request with the asymmetric v2 (Ed25519) protocol. */
export function signZtRequestV2(
  input: ZtSignRequest & { privateKey: KeyObject; kid: string },
): ZtSignedHeadersV2 {
  const roles = normalizeRoles(input.roles);
  const tsMs = input.tsMs ?? Date.now();
  const nonce = input.nonce ?? randomUUID();
  const bodySha256Hex = sha256Hex(input.body);

  const canonical = canonicalizeZtV2({
    alg: 'ed25519',
    kid: input.kid,
    method: input.method,
    path: input.path,
    query: input.query,
    bodySha256Hex,
    userId: input.userId,
    tenantId: input.tenantId,
    roles,
    tsMs,
    nonce,
  });

  const sig = signEd25519(input.privateKey, canonical);

  return {
    'x-zt-v': '2',
    'x-zt-alg': 'ed25519',
    'x-zt-kid': input.kid,
    'x-zt-user-id': input.userId,
    'x-zt-tenant-id': input.tenantId,
    'x-zt-roles': roles,
    'x-zt-ts': String(tsMs),
    'x-zt-nonce': nonce,
    'x-zt-body-sha256': bodySha256Hex,
    'x-zt-sig': sig,
  };
}

/**
 * Signer selected by runtime config. `hmac` keeps the legacy v1 protocol so the
 * flip to `ed25519` is a reversible env change (ZT_SIGN_MODE) with no redeploy
 * of the verifier required.
 */
export type ZtSigner =
  | { mode: 'hmac'; secret: string }
  | { mode: 'ed25519'; privateKey: KeyObject; kid: string };

/** Produce the ZT auth headers for a request using the configured signer. */
export function signZt(
  signer: ZtSigner,
  req: ZtSignRequest,
): Record<string, string> {
  if (signer.mode === 'ed25519') {
    return signZtRequestV2({
      ...req,
      privateKey: signer.privateKey,
      kid: signer.kid,
    });
  }

  return signZtRequest({ ...req, secret: signer.secret });
}

function decodePrivateKeyPem(value: string): string {
  // Accept raw PEM or base64-encoded PEM (env vars dislike multiline values).
  return value.includes('BEGIN')
    ? value
    : Buffer.from(value, 'base64').toString('utf8');
}

/**
 * Build the active signer from ZT config. Fails fast at startup when ed25519
 * mode is selected without a key/kid, rather than per request.
 */
export function buildZtSigner(cfg: {
  signMode: 'hmac' | 'ed25519';
  hmacSecret: string;
  signingKid: string;
  signingPrivateKey: string;
}): ZtSigner {
  if (cfg.signMode === 'ed25519') {
    if (!cfg.signingPrivateKey) {
      throw new Error(
        'ZT_SIGNING_PRIVATE_KEY is required when ZT_SIGN_MODE=ed25519',
      );
    }
    if (!cfg.signingKid) {
      throw new Error('ZT_SIGNING_KID is required when ZT_SIGN_MODE=ed25519');
    }
    const privateKey = createPrivateKey(
      decodePrivateKeyPem(cfg.signingPrivateKey),
    );
    return { mode: 'ed25519', privateKey, kid: cfg.signingKid };
  }

  return { mode: 'hmac', secret: cfg.hmacSecret };
}
