import {
  All,
  Controller,
  ForbiddenException,
  NotFoundException,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { request as undiciRequest } from 'undici';
import { randomUUID } from 'crypto';
import { ConfigService } from '@nestjs/config';

import { JwtVerifyService } from '../auth/jwt-verify.service';
import { PolicyService } from '../policy/policy.service';
import { GatewayService } from './gateway.service';
import { signZtRequest } from '../../common/crypto/hmac-signer';

type ZtCfg = { hmacSecret: string };

function splitUrl(originalUrl: string): { path: string; query: string } {
  const [p, q] = originalUrl.split('?');
  return { path: p ?? '/', query: q ?? '' };
}

function isBodyless(method: string): boolean {
  const m = method.toUpperCase();
  return m === 'GET' || m === 'HEAD';
}

function chunkToBuffer(chunk: unknown): Buffer {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (chunk instanceof Uint8Array) return Buffer.from(chunk);
  if (typeof chunk === 'string') return Buffer.from(chunk);
  throw new Error('Unsupported request body chunk type');
}

/**
 * Lee el body del Request (stream) y lo convierte a Buffer, con límite.
 * Esto evita streaming+undici typing issues y elimina los "unsafe".
 */
async function readReqBodyToBuffer(
  req: Request,
  maxBytes: number,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;

  // Express Request es stream (IncomingMessage), pero typings no siempre exponen AsyncIterable bien.
  for await (const chunk of req as unknown as AsyncIterable<unknown>) {
    const buf = chunkToBuffer(chunk);
    total += buf.length;
    if (total > maxBytes) throw new Error('Body too large');
    chunks.push(buf);
  }

  return Buffer.concat(chunks);
}

@Controller()
export class GatewayController {
  private readonly hmacSecret: string;

  constructor(
    private readonly gw: GatewayService,
    private readonly jwt: JwtVerifyService,
    private readonly policy: PolicyService,
    cfg: ConfigService,
  ) {
    const zt = cfg.get<ZtCfg>('zt');
    if (!zt) throw new Error('Missing zt config');
    this.hmacSecret = zt.hmacSecret;
  }

  /**
   * Catch-all: maneja cualquier método y path.
   * Tip: si querés scoping por prefijo, eso lo resuelve GatewayService con matchPrefix.
   */
  @All('*')
  async handle(@Req() req: Request, @Res() res: Response): Promise<void> {
    const originalUrl = req.originalUrl || req.url || '/';
    const { query } = splitUrl(originalUrl);

    const resolved = this.gw.resolve(req);
    if (!resolved) throw new NotFoundException('No upstream matched');

    const authHeader = req.headers['authorization'];
    const bearer = typeof authHeader === 'string' ? authHeader : undefined;

    const user = this.jwt.verifyBearer(bearer);

    const decision = this.policy.decide({
      upstream: resolved.upstream.name,
      method: req.method,
      path: resolved.upstreamPath,
      roles: user.roles,
    });

    if (!decision.allow) throw new ForbiddenException(decision.reason);

    // Bufferizamos body (MVP safe) para evitar problemas de types/streaming con undici
    const maxBodyBytes = 25 * 1024 * 1024; // 25MB
    const bodyBuf = isBodyless(req.method)
      ? Buffer.alloc(0)
      : await readReqBodyToBuffer(req, maxBodyBytes);

    const signed = signZtRequest({
      secret: this.hmacSecret,
      method: req.method,
      path: resolved.upstreamPath,
      query,
      body: bodyBuf,
      userId: user.sub,
      tenantId: user.tenantId,
      roles: user.roles,
      tsMs: Date.now(),
      nonce: randomUUID(),
    });

    const headers: Record<string, string> = {
      ...signed,
      ...(typeof req.headers['content-type'] === 'string'
        ? { 'content-type': req.headers['content-type'] }
        : {}),
      ...(typeof bearer === 'string' ? { authorization: bearer } : {}),
      // opcional legacy
      'x-tenant-id': user.tenantId,
    };

    const url = new URL(resolved.upstream.baseUrl);
    url.pathname = resolved.upstreamPath;
    url.search = query;

    const upstreamRes = await undiciRequest(url.toString(), {
      method: req.method,
      headers,
      body: isBodyless(req.method) ? undefined : bodyBuf,
    });

    res.status(upstreamRes.statusCode);

    for (const [k, v] of Object.entries(upstreamRes.headers)) {
      if (typeof v === 'string') res.setHeader(k, v);
    }

    // Respuesta como Buffer (evita Readable.fromWeb / pipeTo / casts)
    if (!upstreamRes.body) {
      res.end();
      return;
    }

    const ab = await upstreamRes.body.arrayBuffer();
    const out = Buffer.from(ab);
    res.send(out);
  }
}
