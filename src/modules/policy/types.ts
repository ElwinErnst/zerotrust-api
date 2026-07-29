import { UpstreamName } from '../../config/upstreams.config';

export type PolicyDecision = { allow: true } | { allow: false; reason: string };

export type PolicyInput = {
  upstream: UpstreamName;
  method: string;
  path: string; // path ya “upstream-local” (sin /vault prefix)
  tenantId: string;
  roles: string[];
};
