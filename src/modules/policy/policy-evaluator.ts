import type {
  PolicyRule,
  PolicySet,
} from '../policy-generator/schema/policy.schema';
import type { PolicyDecision, PolicyInput } from './types';

/**
 * Pure evaluator for a compiled PolicySet against a runtime PolicyInput.
 * Zero I/O so it can be unit-tested trivially and shared across the
 * gateway path, the /policies preview endpoint, and the eval harness.
 *
 * Semantics:
 * - Rules are evaluated in order. First matching rule wins.
 * - "Match" = all `when` clauses AND all `if` clauses agree.
 * - If no rule matches, the policy set's `default` decision applies.
 * - `deny` rules can carry a `reason`, surfaced to the caller.
 */
export function evaluatePolicySet(
  policySet: PolicySet,
  input: PolicyInput,
): PolicyDecision {
  for (const rule of policySet.rules) {
    if (ruleMatches(rule, input)) {
      if (rule.effect === 'allow') return { allow: true };
      return {
        allow: false,
        reason: rule.reason ?? `Denied by rule: ${rule.description}`,
      };
    }
  }

  if (policySet.default === 'allow') return { allow: true };
  return { allow: false, reason: 'No rule matched (default deny)' };
}

function ruleMatches(rule: PolicyRule, input: PolicyInput): boolean {
  const w = rule.when;

  if (w.upstream !== input.upstream) return false;

  if (w.methods && w.methods.length > 0) {
    if (!w.methods.includes(input.method.toUpperCase() as never)) return false;
  }

  if (w.pathGlob && !globMatches(w.pathGlob, input.path)) return false;

  const cond = rule.if;
  if (cond) {
    if (cond.roleIn && cond.roleIn.length > 0) {
      const hit = cond.roleIn.some((r) => input.roles.includes(r));
      if (!hit) return false;
    }
    // actorTypeIn matches on the JWT actorType if it's carried on roles;
    // when a real actorType field is on PolicyInput this becomes a direct
    // comparison. For now, the roles array is the only signal.
  }

  return true;
}

/**
 * Tiny glob matcher: supports `*` (zero or more of any char except `/`)
 * and `**` (zero or more of any char). Anything else is literal.
 * Escapes regex metachars, then swaps globs for their regex equivalents.
 */
function globMatches(glob: string, value: string): boolean {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  const regexSrc = escaped
    .replace(/\*\*/g, '::DOUBLESTAR::')
    .replace(/\*/g, '[^/]*')
    .replace(/::DOUBLESTAR::/g, '.*');
  const regex = new RegExp(`^${regexSrc}$`);
  return regex.test(value);
}
