// src/common/zt/zt-verify.ts
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'crypto';
import {
  sha256Hex,
  type ZtSignedHeaders,
  signZtRequest,
} from '../crypto/hmac-signer';

type HeaderValue = string | string[] | undefined;

function firstHeader(v: HeaderValue): string | null {
  if (typeof v === 'string') return v;
  if (Array.isArray(v) && typeof v[0] === 'string') return v[0];
  return null;
}

function requireHeader(v: HeaderValue, name: string): string {
  const x = firstHeader(v);
  if (!x) throw new BadRequestException(`Missing header: ${name}`);
  return x;
}

function isHex64(x: string): boolean {
  return /^[0-9a-f]{64}$/i.test(x.trim());
}

function isIntString(x: string): boolean {
  return /^[0-9]+$/.test(x.trim());
}

export type ZtVerified = {
  userId: string;
  tenantId: string;
  roles: string[]; // ya normalizadas, upper
  tsMs: number;
  nonce: string;
  bodySha256: string; // hex
};

/**
 * Verifica headers ZT.
 * - method/path/query vienen del request "real" que estás procesando (lo que protege contra tampering).
 * - body debe ser el body raw (Buffer.alloc(0) si no hay).
 */
export function verifyZtHeaders(input: {
  secret: string;

  method: string;
  path: string; // sin query
  query: string; // sin '?', o ""

  body: Buffer;

  headers: Record<string, HeaderValue>;
  maxSkewMs?: number; // tolerancia reloj
}): ZtVerified {
  const maxSkewMs = input.maxSkewMs ?? 2 * 60 * 1000; // 2 min

  const v = requireHeader(input.headers['x-zt-v'], 'x-zt-v');
  if (v !== '1') throw new BadRequestException('Invalid x-zt-v');

  const userId = requireHeader(input.headers['x-zt-user-id'], 'x-zt-user-id');
  const tenantId = requireHeader(
    input.headers['x-zt-tenant-id'],
    'x-zt-tenant-id',
  );
  const rolesRaw = requireHeader(input.headers['x-zt-roles'], 'x-zt-roles');
  const tsRaw = requireHeader(input.headers['x-zt-ts'], 'x-zt-ts');
  const nonce = requireHeader(input.headers['x-zt-nonce'], 'x-zt-nonce');
  const bodySha = requireHeader(
    input.headers['x-zt-body-sha256'],
    'x-zt-body-sha256',
  );
  const sig = requireHeader(input.headers['x-zt-sig'], 'x-zt-sig');

  if (!isIntString(tsRaw)) throw new BadRequestException('Invalid x-zt-ts');
  const tsMs = Number(tsRaw);

  const now = Date.now();
  if (Math.abs(now - tsMs) > maxSkewMs) {
    throw new ForbiddenException('ZT timestamp outside allowed skew');
  }

  const computedBodySha = sha256Hex(input.body);
  if (!isHex64(bodySha) || bodySha.toLowerCase() !== computedBodySha) {
    throw new ForbiddenException('ZT body hash mismatch');
  }

  // roles: "ADMIN,MEMBER"
  const roles = rolesRaw
    .split(',')
    .map((r) => r.trim().toUpperCase())
    .filter(Boolean);

  // Re-firmamos con los mismos datos y comparamos sig constant-time
  const expected: ZtSignedHeaders = signZtRequest({
    secret: input.secret,
    method: input.method,
    path: input.path,
    query: input.query,
    body: input.body,
    userId,
    tenantId,
    roles,
    tsMs,
    nonce,
  });

  // constant-time compare
  const a = Buffer.from(sig, 'hex');
  const b = Buffer.from(expected['x-zt-sig'], 'hex');

  // si no son mismo largo, timingSafeEqual revienta => rechazamos
  if (a.length !== b.length)
    throw new ForbiddenException('ZT signature invalid');
  if (!timingSafeEqual(a, b))
    throw new ForbiddenException('ZT signature invalid');

  return { userId, tenantId, roles, tsMs, nonce, bodySha256: computedBodySha };
}

/**
 * Helper opcional para “firma cruda” (si querés comparar sin signZtRequest).
 * No lo uses si ya usás signZtRequest.
 */
export function hmacHex(secret: string, canonical: string): string {
  return createHmac('sha256', secret).update(canonical).digest('hex');
}
