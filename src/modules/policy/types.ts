import { UpstreamName } from '../../config/upstreams.config';

export type PolicyDecision = { allow: true } | { allow: false; reason: string };

export type PolicyInput = {
  upstream: UpstreamName;
  method: string;
  path: string; // path ya “upstream-local” (sin /vault prefix)
  tenantId: string;
  roles: string[];
  // Caller kind, from the JWT. Lets rules match on `actorTypeIn`
  // (human vs machine) independently of the role list.
  actorType?: 'user' | 'service_account';
};
