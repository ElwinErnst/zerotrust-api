import { evaluatePolicySet } from './policy-evaluator';
import type { PolicyInput } from './types';
import type { PolicySet } from '../policy-generator/schema/policy.schema';

// Mirrors the "service accounts blocked, users allowed" intent: a machine-only
// deny rule first, a human allow rule second, default deny. Exercises the
// actorTypeIn matching that the evaluator previously ignored.
const denyServiceAccountsPolicy: PolicySet = {
  version: 1,
  default: 'deny',
  rules: [
    {
      description: 'Deny all service accounts on vault',
      effect: 'deny',
      when: { upstream: 'vault' },
      if: { actorTypeIn: ['service_account'] },
      reason: 'service accounts are not allowed on vault',
    },
    {
      description: 'Allow OWNER and ADMIN on vault',
      effect: 'allow',
      when: { upstream: 'vault' },
      if: { roleIn: ['OWNER', 'ADMIN'] },
    },
  ],
};

const baseInput: Omit<PolicyInput, 'roles' | 'actorType'> = {
  upstream: 'vault',
  method: 'GET',
  path: '/vaults',
  tenantId: 'tenant-a',
};

describe('evaluatePolicySet — actorTypeIn matching', () => {
  it('allows a human OWNER even when a deny-service_account rule precedes the allow', () => {
    const decision = evaluatePolicySet(denyServiceAccountsPolicy, {
      ...baseInput,
      roles: ['OWNER'],
      actorType: 'user',
    });
    // Regression guard: the deny rule must NOT trip on a user. Before the fix,
    // actorTypeIn was ignored and this OWNER was denied by the first rule.
    expect(decision).toEqual({ allow: true });
  });

  it('denies a service account via actorTypeIn', () => {
    const decision = evaluatePolicySet(denyServiceAccountsPolicy, {
      ...baseInput,
      roles: ['API_CLIENT'],
      actorType: 'service_account',
    });
    expect(decision.allow).toBe(false);
  });

  it('does not trip an actorTypeIn rule when actorType is unknown', () => {
    // No actorType on the input: the deny rule cannot be confirmed, so it is
    // skipped and the OWNER falls through to the allow rule.
    const decision = evaluatePolicySet(denyServiceAccountsPolicy, {
      ...baseInput,
      roles: ['OWNER'],
    });
    expect(decision).toEqual({ allow: true });
  });
});
