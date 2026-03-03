import type { Request, Response } from 'express';
import { request as undiciRequest } from 'undici';

export async function proxyToUpstream(opts: {
  req: Request;
  res: Response;
  url: string;
  headers: Record<string, string>;
}): Promise<void> {
  const { req, res, url, headers } = opts;

  const method = req.method.toUpperCase();
  const body = method === 'GET' || method === 'HEAD' ? undefined : req;

  const upstreamRes = await undiciRequest(url, {
    method,
    headers,
    body,
  });

  res.status(upstreamRes.statusCode);

  // forward algunos headers de respuesta (evitar hop-by-hop)
  const blocked = new Set([
    'connection',
    'keep-alive',
    'transfer-encoding',
    'upgrade',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
  ]);

  for (const [k, v] of Object.entries(upstreamRes.headers)) {
    if (blocked.has(k.toLowerCase())) continue;
    if (typeof v === 'string') res.setHeader(k, v);
  }

  if (!upstreamRes.body) {
    res.end();
    return;
  }

  upstreamRes.body.pipe(res);
}
