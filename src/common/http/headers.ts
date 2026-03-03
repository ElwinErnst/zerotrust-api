import type { Request } from 'express';

export function pickForwardHeaders(req: Request): Record<string, string> {
  const out: Record<string, string> = {};

  const ct = req.headers['content-type'];
  if (typeof ct === 'string') out['content-type'] = ct;

  const accept = req.headers['accept'];
  if (typeof accept === 'string') out['accept'] = accept;

  const ua = req.headers['user-agent'];
  if (typeof ua === 'string') out['user-agent'] = ua;

  // NO forward cookies por defecto (zero trust)
  // NO forward host
  // NO forward connection headers

  return out;
}
