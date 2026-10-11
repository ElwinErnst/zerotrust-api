# Feature: ZT generic multi-upstream — vertical validation slice

## Objective
Prove end-to-end, in zerotrust-api ONLY, that a second **non-vault** upstream can be
routed, policy-enforced, signed (Ed25519), SSRF-guarded, and verified by the upstream —
using the **existing file-based registry** (`ZT_UPSTREAMS_FILE` + `AdminService`), WITHOUT
building the per-tenant auth-api registry or the console yet. This de-risks the larger
self-service plan cheaply. Vault behavior must not regress.

## Why / context
Driver: PaaS customers (future) connecting their own apps behind ZT. No immediate consumer,
so this is a cheap architecture-validation slice. Full plan (self-service via auth-api,
console UI, JWKS/SDK) is in the superproject plan file and deferred until this validates.

## Current pins (verified)
- `src/config/upstreams.config.ts:3` `UpstreamName = 'vault'` literal; single hardcoded entry.
- `src/modules/gateway/gateway.controller.ts:117` `@Controller('vault')` — ingress route pinned.
- `src/modules/gateway/gateway.service.ts` `resolve()` prefix match is ALREADY generic.
- `src/modules/policy/policy.service.ts:41-43` hard-deny `upstream !== 'vault'`.
- `src/modules/admin/admin.service.ts` already loads `ZT_UPSTREAMS_FILE` (`UpstreamSchema.name = z.string()`) but GatewayService does NOT consume it (latent seam).
- Ed25519 signer (`src/common/crypto/zt-v2-signer.ts`, `canonical.ts`) payload is upstream-agnostic.
- Dormant verifier `src/common/zt/zt.guard.ts` (ZtGuard + replay cache) = the customer-side verifier reference.
- Outbound forward (`gateway.controller.ts`) has NO SSRF guard, NO outbound timeout, NO redirect control.
- No gateway tests exist.

## Scope (this slice)
IN:
- Generalize `UpstreamName` (literal → string) and `PolicyInput.upstream`.
- Make `GatewayService` consume the merged upstream set: the built-in `vault` + entries from
  the file registry (`ZT_UPSTREAMS_FILE` via AdminService). Global prefixes (NOT per-tenant yet).
- Generalize the ingress controller so non-vault prefixes route (remove the `@Controller('vault')` pin; mount generically / add route; vault keeps working).
- Policy: remove the `upstream !== 'vault'` hard-deny. For a non-vault upstream: run
  `evaluatePolicySet` if a policy is present; else a minimal coarse default (require a human
  role, default-deny for anonymous/unknown). Do NOT apply vault-specific feature ceilings or
  vault RBAC routes to non-vault upstreams.
- SSRF/egress guard before forwarding: block private/link-local/loopback/metadata IP ranges
  (incl. 169.254.169.254, 10/8, 172.16/12, 192.168/16, 127/8, ::1, fc00::/7), validate the
  resolved IP (basic DNS-rebind defense), add an outbound timeout (AbortController, mirror
  `auth-directory.service.ts` pattern), disable redirect following.
- Make the vault-specific billing metering block skip/no-op for non-vault upstreams (don't break).
- Tests (none exist today): a registered non-vault upstream routes + policy allow/deny; SSRF
  guard rejects a private/metadata host; sign→verify round-trip using ZtGuard (proves a
  customer app can verify a gateway-signed request).

OUT (deferred):
- auth-api per-tenant upstream registry, tenant-scoped routing, console UI, entitlement
  (`features.gateway`), JWKS endpoint + verifier SDK, per-upstream keypairs. Keep one shared
  ZT signing keypair.

## TDD / verification
No TDD mode configured here; tests exist via Jest. Verification = `npm run build` + `npm test`
green, plus the new gateway/SSRF/round-trip tests pass. Confirm vault path unchanged (regression).

## Tasks
- [x] T1 — Generalized `UpstreamName` (literal→string) + `VAULT_UPSTREAM_NAME` const; `GatewayService` merges built-in vault + file registry (`AdminService.getUpstreams()`), with a safety filter (registered upstreams must use the reserved `/gw/` prefix and may not reuse a built-in name). `GatewayModule` imports `AdminModule`.
- [x] T2 — Controller is now `@Controller(['vault','gw'])`; `/vault/*` unchanged, `/gw/*` routes registered upstreams via the already-generic `resolve()`.
- [x] T3 — Dropped the `upstream !== 'vault'` hard deny; `decide()` branches: vault keeps ceilings+RBAC+custom-policy; generic upstream = published PolicySet decides, else coarse default `requireRole('MEMBER')` (denies API clients/anon).
- [x] T4 — New `src/common/http/ssrf.ts` (`assertUpstreamUrlSafe` + `isBlockedIp`): blocks private/loopback/link-local/metadata/ULA/CGNAT, resolves A/AAAA (basic DNS-rebind), http(s)-only. Applied to non-built-in upstreams before forward; added AbortController timeout (15s → 504) + BadGateway on failure; undici doesn't follow redirects by default.
- [x] T5 — Metering block was already gated to `vault`; added a clarifying comment (non-vault not metered this slice).
- [x] T6 — New specs: `gateway.service.spec.ts`, `common/http/ssrf.spec.ts`, `common/zt/zt-roundtrip.spec.ts`, `policy.service.generic-upstream.spec.ts`. Evidence: `npm run build` green; `npm test` → 11 suites / 72 tests passed (incl. vault regression specs).

## Acceptance
- A non-vault upstream (toy, from ZT_UPSTREAMS_FILE) is routed, policy-enforced, signed, and
  forwarded; SSRF guard blocks private/metadata targets; a ZtGuard round-trip verifies the
  signature. `npm run build` + `npm test` green. Vault path unchanged.
