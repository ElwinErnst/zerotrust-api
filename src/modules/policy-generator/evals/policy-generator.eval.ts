import 'reflect-metadata';
import { ConfigService } from '@nestjs/config';
import policyGeneratorConfig from '../../../config/policy-generator.config';
import { evaluatePolicySet } from '../../policy/policy-evaluator';
import type { PolicyDecision } from '../../policy/types';
import { PolicyGeneratorService } from '../policy-generator.service';
import { POLICY_FIXTURES } from './fixtures';

/**
 * Offline semantic eval for the LLM policy generator.
 *
 * For each fixture we ask Claude to compile the intent to a PolicySet, then
 * evaluate every expectation with the pure evaluator. A fixture passes iff
 * ALL expectations return the expected decision. This is stricter than a
 * per-decision accuracy because a single wrong rule can break several
 * expectations at once — which is exactly what we want to catch.
 *
 * Run:
 *   docker exec sentinel-suite-zerotrust-api-1 \
 *     node dist/modules/policy-generator/evals/policy-generator.eval.js
 */

const PRICING: Record<string, { input: number; output: number }> = {
  'claude-sonnet-5': { input: 3, output: 15 },
};

function decisionsEqual(a: PolicyDecision, b: PolicyDecision): boolean {
  // Only compare on `allow` — a fixture that expects a deny does not pin the
  // reason string. The evaluator surfaces different reasons depending on
  // whether the deny came from an explicit rule or from `default: deny`.
  return a.allow === b.allow;
}

async function main(): Promise<void> {
  const cfg = await policyGeneratorConfig();
  const configService = { get: () => cfg } as unknown as ConfigService;
  const service = new PolicyGeneratorService(configService);

  if (!service.isEnabled) {
    console.error(
      'Generator disabled. Set POLICY_GENERATOR_ENABLED=true and ANTHROPIC_API_KEY.',
    );
    process.exit(1);
  }

  console.log(
    `Running ${POLICY_FIXTURES.length} fixtures against ${cfg.model}...\n`,
  );

  const latencies: number[] = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalWarnings = 0;
  let passedFixtures = 0;
  let totalExpectations = 0;
  let passedExpectations = 0;
  let generationErrors = 0;

  for (const fx of POLICY_FIXTURES) {
    process.stdout.write(`- ${fx.name} ... `);
    try {
      const result = await service.generate({ intent: fx.intent });
      latencies.push(result.latencyMs);
      totalInputTokens += result.tokens.input;
      totalOutputTokens += result.tokens.output;
      totalWarnings += result.warnings.length;

      let fixturePassed = true;
      const failedExpectations: string[] = [];
      for (const exp of fx.expectations) {
        totalExpectations += 1;
        const got = evaluatePolicySet(result.policy, exp.input);
        if (decisionsEqual(got, exp.expected)) {
          passedExpectations += 1;
        } else {
          fixturePassed = false;
          const inputDesc = `${exp.input.method} ${exp.input.path} as [${exp.input.roles.join(',')}]`;
          failedExpectations.push(
            `${inputDesc}: expected ${JSON.stringify(exp.expected)}, got ${JSON.stringify(got)}${exp.note ? ` (${exp.note})` : ''}`,
          );
        }
      }
      if (fixturePassed) {
        passedFixtures += 1;
        console.log(
          `OK (${fx.expectations.length}/${fx.expectations.length} expectations, ${result.latencyMs}ms, ${result.warnings.length} warnings)`,
        );
      } else {
        console.log(
          `FAIL (${fx.expectations.length - failedExpectations.length}/${fx.expectations.length} expectations, ${result.latencyMs}ms)`,
        );
        for (const msg of failedExpectations) {
          console.log(`      → ${msg}`);
        }
      }
    } catch (err) {
      generationErrors += 1;
      console.log(
        `ERROR (${err instanceof Error ? err.message : String(err)})`,
      );
    }
  }

  const p = (q: number) => {
    if (latencies.length === 0) return 0;
    const sorted = [...latencies].sort((a, b) => a - b);
    const idx = Math.min(
      sorted.length - 1,
      Math.ceil((q / 100) * sorted.length) - 1,
    );
    return sorted[idx];
  };

  const pricing = PRICING[cfg.model] ?? { input: 0, output: 0 };
  const totalCostUsd =
    (totalInputTokens / 1_000_000) * pricing.input +
    (totalOutputTokens / 1_000_000) * pricing.output;

  console.log(`\n=== Aggregate ===`);
  console.log(
    `fixtures passed:      ${passedFixtures}/${POLICY_FIXTURES.length}`,
  );
  console.log(
    `expectations passed:  ${passedExpectations}/${totalExpectations}`,
  );
  console.log(`generation errors:    ${generationErrors}`);
  console.log(`avg warnings/fixture: ${(totalWarnings / POLICY_FIXTURES.length).toFixed(1)}`);
  console.log(`latency p50:          ${p(50)}ms`);
  console.log(`latency p95:          ${p(95)}ms`);
  console.log(
    `avg tokens:           in=${Math.round(totalInputTokens / Math.max(1, latencies.length))} out=${Math.round(totalOutputTokens / Math.max(1, latencies.length))}`,
  );
  console.log(
    `total cost:           $${totalCostUsd.toFixed(4)} (${latencies.length} generations)`,
  );
  console.log(
    `cost/generation:      $${(totalCostUsd / Math.max(1, latencies.length)).toFixed(5)}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
