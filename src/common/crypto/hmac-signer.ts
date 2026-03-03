import { createHmac, createHash, randomUUID } from 'crypto';
import { canonicalizeZt } from './canonical';

export type ZtSignedHeaders = {
  'x-zt-v': '1';
  'x-zt-user-id': string;
  'x-zt-tenant-id': string;
  'x-zt-roles': string;
  'x-zt-ts': string;
  'x-zt-nonce': string;
  'x-zt-body-sha256': string; // hex
  'x-zt-sig': string; // hex
};

export function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function normalizeRoles(roles: readonly string[]): string {
  return [...roles]
    .map((r) => r.trim().toUpperCase())
    .filter(Boolean)
    .sort()
    .join(',');
}

export function signZtRequest(input: {
  secret: string;
  method: string;
  path: string; // sin query
  query: string; // sin '?'
  body: Buffer; // si no hay body => Buffer.alloc(0)
  userId: string;
  tenantId: string;
  roles: readonly string[];
  tsMs?: number;
  nonce?: string;
}): ZtSignedHeaders {
  if (!input.secret) throw new Error('Missing HMAC secret');

  const roles = normalizeRoles(input.roles);
  const tsMs = input.tsMs ?? Date.now();
  const nonce = input.nonce ?? randomUUID();

  const bodySha256Hex = sha256Hex(input.body);

  const canonical = canonicalizeZt({
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

  const sig = createHmac('sha256', input.secret)
    .update(canonical)
    .digest('hex');

  return {
    'x-zt-v': '1',
    'x-zt-user-id': input.userId,
    'x-zt-tenant-id': input.tenantId,
    'x-zt-roles': roles,
    'x-zt-ts': String(tsMs),
    'x-zt-nonce': nonce,
    'x-zt-body-sha256': bodySha256Hex,
    'x-zt-sig': sig,
  };
}
