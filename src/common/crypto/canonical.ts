export type CanonicalZtInput = {
  method: string;
  path: string;
  query: string; // sin "?" (ej: "a=1&b=2") o "" si no hay
  bodySha256Hex: string; // 64 hex (sha256)
  userId: string;
  tenantId: string;
  roles: string; // normalizados: "ADMIN,MEMBER"
  tsMs: number;
  nonce: string;
};

function normMethod(m: string): string {
  return m.trim().toUpperCase();
}

function normPath(p: string): string {
  const x = p.trim();
  if (!x) return '/';
  return x.startsWith('/') ? x : `/${x}`;
}

function normQuery(q: string): string {
  return q.trim().replace(/^\?/, '');
}

function normHex64(hex: string): string {
  const h = hex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) {
    throw new Error('Invalid bodySha256Hex (expected 64 hex chars)');
  }
  return h;
}

export function canonicalizeZt(input: CanonicalZtInput): string {
  const method = normMethod(input.method);
  const path = normPath(input.path);
  const query = normQuery(input.query);
  const bodySha256Hex = normHex64(input.bodySha256Hex);

  return [
    `v:1`,
    `method:${method}`,
    `path:${path}`,
    `query:${query}`,
    `body_sha256:${bodySha256Hex}`,
    `user_id:${input.userId}`,
    `tenant_id:${input.tenantId}`,
    `roles:${input.roles}`,
    `ts:${String(input.tsMs)}`,
    `nonce:${input.nonce}`,
  ].join('\n');
}
