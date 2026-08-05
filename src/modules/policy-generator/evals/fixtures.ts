import type {
  PolicyDecision,
  PolicyInput,
} from '../../policy/types';

/**
 * A fixture is a natural-language intent plus a set of `expectations`.
 * Each expectation is a synthetic PolicyInput that we run through the
 * generated policy's evaluator, together with the decision we should get.
 * A fixture passes iff every expectation returns the expected decision.
 *
 * This is a semantic eval — we don't compare the generated JSON to a
 * hand-written one. Two different policies with the same behavior both
 * count as correct. Focus is on outcome, not shape.
 */
export type PolicyFixture = {
  name: string;
  intent: string;
  expectations: Array<{
    input: PolicyInput;
    expected: PolicyDecision;
    note?: string;
  }>;
};

// Standard synthetic inputs used across fixtures.
const owner = (extra: Partial<PolicyInput> = {}): PolicyInput => ({
  upstream: 'vault',
  method: 'GET',
  path: '/vaults',
  tenantId: 'tenant-a',
  roles: ['OWNER'],
  ...extra,
});
const admin = (extra: Partial<PolicyInput> = {}): PolicyInput => ({
  upstream: 'vault',
  method: 'GET',
  path: '/vaults',
  tenantId: 'tenant-a',
  roles: ['ADMIN'],
  ...extra,
});
const member = (extra: Partial<PolicyInput> = {}): PolicyInput => ({
  upstream: 'vault',
  method: 'GET',
  path: '/vaults',
  tenantId: 'tenant-a',
  roles: ['MEMBER'],
  ...extra,
});

const allow: PolicyDecision = { allow: true };
const deny = (reason?: string): PolicyDecision => ({
  allow: false,
  reason: reason ?? '',
});

export const POLICY_FIXTURES: PolicyFixture[] = [
  {
    name: 'owner all, member read-only vaults',
    intent:
      'OWNER can do anything on vault. MEMBER can only GET /vaults. Everyone else is denied.',
    expectations: [
      { input: owner({ method: 'POST', path: '/documents' }), expected: allow },
      { input: owner({ method: 'DELETE', path: '/vaults/abc' }), expected: allow },
      { input: member(), expected: allow },
      {
        input: member({ method: 'POST', path: '/vaults' }),
        expected: deny(),
        note: 'MEMBER POST is not explicitly allowed',
      },
      {
        input: member({ method: 'GET', path: '/documents' }),
        expected: deny(),
        note: 'MEMBER can only GET /vaults per intent',
      },
    ],
  },
  {
    name: 'admin can manage documents, member read only',
    intent:
      'ADMIN can create, read, update and delete documents. MEMBER can only read documents. Default deny.',
    expectations: [
      { input: admin({ method: 'POST', path: '/documents' }), expected: allow },
      { input: admin({ method: 'DELETE', path: '/documents/x' }), expected: allow },
      { input: member({ method: 'GET', path: '/documents' }), expected: allow },
      {
        input: member({ method: 'POST', path: '/documents' }),
        expected: deny(),
      },
    ],
  },
  {
    name: 'deny all by default',
    intent:
      'Deny everything. Nobody can touch anything on vault, auth or billing.',
    expectations: [
      { input: owner(), expected: deny() },
      { input: admin({ method: 'POST', path: '/documents' }), expected: deny() },
      { input: member({ method: 'GET', path: '/vaults' }), expected: deny() },
    ],
  },
  {
    name: 'read-only for everyone',
    intent:
      'All roles (OWNER, ADMIN, MEMBER) can perform GET requests on vault. No writes allowed.',
    expectations: [
      { input: owner({ method: 'GET', path: '/vaults' }), expected: allow },
      { input: admin({ method: 'GET', path: '/documents' }), expected: allow },
      { input: member({ method: 'GET', path: '/documents/xyz' }), expected: allow },
      { input: owner({ method: 'POST', path: '/vaults' }), expected: deny() },
      { input: admin({ method: 'PUT', path: '/vaults/x' }), expected: deny() },
      { input: member({ method: 'DELETE', path: '/vaults/x' }), expected: deny() },
    ],
  },
  {
    name: 'explicit deny on delete',
    intent:
      'OWNER can do anything on vault EXCEPT DELETE. All DELETE requests should be rejected.',
    expectations: [
      { input: owner({ method: 'GET', path: '/vaults' }), expected: allow },
      { input: owner({ method: 'POST', path: '/documents' }), expected: allow },
      { input: owner({ method: 'DELETE', path: '/documents/x' }), expected: deny() },
      { input: admin({ method: 'DELETE', path: '/vaults/x' }), expected: deny() },
    ],
  },
  {
    name: 'method array policy',
    intent:
      'MEMBER can GET and POST /documents on vault. All other requests are denied.',
    expectations: [
      { input: member({ method: 'GET', path: '/documents' }), expected: allow },
      { input: member({ method: 'POST', path: '/documents' }), expected: allow },
      { input: member({ method: 'DELETE', path: '/documents/x' }), expected: deny() },
      { input: member({ method: 'PATCH', path: '/documents/x' }), expected: deny() },
    ],
  },
  {
    name: 'glob path scope',
    intent:
      'ADMIN can access anything under /documents on vault (all methods). Everything else denied.',
    expectations: [
      { input: admin({ method: 'GET', path: '/documents' }), expected: allow },
      { input: admin({ method: 'GET', path: '/documents/x' }), expected: allow },
      { input: admin({ method: 'DELETE', path: '/documents/deep/nested/x' }), expected: allow },
      { input: admin({ method: 'GET', path: '/vaults' }), expected: deny() },
      { input: admin({ method: 'GET', path: '/other' }), expected: deny() },
    ],
  },
  {
    name: 'service accounts blocked, users allowed',
    intent:
      'Users with OWNER or ADMIN roles can access vault. Service accounts are completely denied on vault.',
    expectations: [
      { input: owner({ roles: ['OWNER'] }), expected: allow },
      { input: admin({ roles: ['ADMIN'] }), expected: allow },
      {
        input: { ...owner(), roles: ['API_CLIENT'] },
        expected: deny(),
        note: 'service account role is not in OWNER/ADMIN allowlist',
      },
    ],
  },
];
