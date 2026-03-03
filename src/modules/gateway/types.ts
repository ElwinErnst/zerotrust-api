import { UpstreamConfig } from '../../config/upstreams.config';

export type ResolvedUpstream = {
  upstream: UpstreamConfig;
  upstreamPath: string; // path sin el prefix (/vault)
};
