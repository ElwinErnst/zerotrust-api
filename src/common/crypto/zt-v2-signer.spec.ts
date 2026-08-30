import { createHash } from 'crypto';
import { canonicalizeZtV2 } from './canonical';
import { generateEd25519KeyPair, signEd25519, verifyEd25519 } from './ed25519';
import {
  buildZtSigner,
  signZt,
  signZtRequestV2,
  type ZtSigner,
} from './zt-v2-signer';

// This golden string is byte-identical to what securechain-vault's
// canonicalizeZtV2 produces for the same input. It is the cross-repo guard
// against canonicalization drift between the signer (here) and the verifier
// (vault). If this test breaks, the two services will reject each other.
const GOLDEN_BODY_SHA =
  '4d4bbe59c6aad22442cde199a6a8a5f034405fcd78fb5a81c24ef249de1c45f1';
const GOLDEN_CANONICAL = [
  'v:2',
  'alg:ed25519',
  'kid:zt-golden-kid',
  'method:POST',
  'path:/documents',
  'query:a=1&b=2',
  `body_sha256:${GOLDEN_BODY_SHA}`,
  'user_id:user-1',
  'tenant_id:tenant-1',
  'roles:ADMIN,MEMBER',
  'ts:1700000000000',
  'nonce:fixed-nonce',
].join('\n');

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

describe('canonicalizeZtV2 golden vector (cross-repo)', () => {
  it('matches the vault verifier byte-for-byte', () => {
    const body = Buffer.from('{"amount":100}');
    expect(sha256Hex(body)).toBe(GOLDEN_BODY_SHA);

    const canonical = canonicalizeZtV2({
      alg: 'ed25519',
      kid: 'zt-golden-kid',
      method: 'POST',
      path: '/documents',
      query: 'a=1&b=2',
      bodySha256Hex: GOLDEN_BODY_SHA,
      userId: 'user-1',
      tenantId: 'tenant-1',
      roles: 'ADMIN,MEMBER',
      tsMs: 1700000000000,
      nonce: 'fixed-nonce',
    });

    expect(canonical).toBe(GOLDEN_CANONICAL);
  });
});

describe('Ed25519 sign/verify round-trip', () => {
  it('verifies a signature made with the matching key', () => {
    const keys = generateEd25519KeyPair();
    const sig = signEd25519(keys.privateKey, GOLDEN_CANONICAL);
    expect(verifyEd25519(keys.publicKey, GOLDEN_CANONICAL, sig)).toBe(true);
  });

  it('rejects a signature from a different key', () => {
    const keys = generateEd25519KeyPair();
    const other = generateEd25519KeyPair();
    const sig = signEd25519(other.privateKey, GOLDEN_CANONICAL);
    expect(verifyEd25519(keys.publicKey, GOLDEN_CANONICAL, sig)).toBe(false);
  });
});

describe('signZtRequestV2', () => {
  const keys = generateEd25519KeyPair();

  it('emits v2 headers whose signature verifies over the rebuilt canonical', () => {
    const body = Buffer.from('{"hello":"world"}');
    const headers = signZtRequestV2({
      privateKey: keys.privateKey,
      kid: 'zt-2026-08',
      method: 'POST',
      path: '/documents',
      query: 'a=1',
      body,
      userId: 'user-9',
      tenantId: 'tenant-9',
      roles: ['member', 'ADMIN'],
      tsMs: 1700000000000,
      nonce: 'n-1',
    });

    expect(headers['x-zt-v']).toBe('2');
    expect(headers['x-zt-alg']).toBe('ed25519');
    expect(headers['x-zt-kid']).toBe('zt-2026-08');
    // roles are normalized (upper + sorted), same rule as v1.
    expect(headers['x-zt-roles']).toBe('ADMIN,MEMBER');
    expect(headers['x-zt-body-sha256']).toBe(sha256Hex(body));

    const rebuilt = canonicalizeZtV2({
      alg: 'ed25519',
      kid: headers['x-zt-kid'],
      method: 'POST',
      path: '/documents',
      query: 'a=1',
      bodySha256Hex: headers['x-zt-body-sha256'],
      userId: headers['x-zt-user-id'],
      tenantId: headers['x-zt-tenant-id'],
      roles: headers['x-zt-roles'],
      tsMs: Number(headers['x-zt-ts']),
      nonce: headers['x-zt-nonce'],
    });
    expect(verifyEd25519(keys.publicKey, rebuilt, headers['x-zt-sig'])).toBe(
      true,
    );
  });
});

describe('signZt dispatch by mode', () => {
  const req = {
    method: 'GET',
    path: '/documents',
    query: '',
    body: Buffer.alloc(0),
    userId: 'user-1',
    tenantId: 'tenant-1',
    roles: ['ADMIN'],
    tsMs: 1700000000000,
    nonce: 'n-2',
  };

  it('produces v1 HMAC headers in hmac mode', () => {
    const signer: ZtSigner = { mode: 'hmac', secret: 'test-secret' };
    const headers = signZt(signer, req);
    expect(headers['x-zt-v']).toBe('1');
    expect(headers['x-zt-sig']).toMatch(/^[0-9a-f]{64}$/);
    expect(headers['x-zt-kid']).toBeUndefined();
  });

  it('produces v2 Ed25519 headers in ed25519 mode', () => {
    const keys = generateEd25519KeyPair();
    const signer: ZtSigner = {
      mode: 'ed25519',
      privateKey: keys.privateKey,
      kid: 'zt-2026-08',
    };
    const headers = signZt(signer, req);
    expect(headers['x-zt-v']).toBe('2');
    expect(headers['x-zt-kid']).toBe('zt-2026-08');

    const rebuilt = canonicalizeZtV2({
      alg: 'ed25519',
      kid: 'zt-2026-08',
      method: 'GET',
      path: '/documents',
      query: '',
      bodySha256Hex: headers['x-zt-body-sha256'],
      userId: 'user-1',
      tenantId: 'tenant-1',
      roles: 'ADMIN',
      tsMs: 1700000000000,
      nonce: 'n-2',
    });
    expect(verifyEd25519(keys.publicKey, rebuilt, headers['x-zt-sig'])).toBe(
      true,
    );
  });
});

describe('buildZtSigner', () => {
  it('defaults to hmac mode', () => {
    const signer = buildZtSigner({
      signMode: 'hmac',
      hmacSecret: 's',
      signingKid: '',
      signingPrivateKey: '',
    });
    expect(signer.mode).toBe('hmac');
  });

  it('throws when ed25519 mode lacks a private key', () => {
    expect(() =>
      buildZtSigner({
        signMode: 'ed25519',
        hmacSecret: 's',
        signingKid: 'kid',
        signingPrivateKey: '',
      }),
    ).toThrow(/ZT_SIGNING_PRIVATE_KEY/);
  });

  it('accepts a base64-encoded PEM private key', () => {
    const keys = generateEd25519KeyPair();
    const pem = keys.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const signer = buildZtSigner({
      signMode: 'ed25519',
      hmacSecret: 's',
      signingKid: 'kid-1',
      signingPrivateKey: Buffer.from(pem).toString('base64'),
    });
    expect(signer.mode).toBe('ed25519');

    const headers = signZt(signer, {
      method: 'GET',
      path: '/x',
      query: '',
      body: Buffer.alloc(0),
      userId: 'u',
      tenantId: 't',
      roles: ['ADMIN'],
      tsMs: 1700000000000,
      nonce: 'n',
    });
    expect(headers['x-zt-v']).toBe('2');
    expect(headers['x-zt-kid']).toBe('kid-1');
  });
});
