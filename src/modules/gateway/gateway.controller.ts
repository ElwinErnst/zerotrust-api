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
import { BillingMeteringService } from '../../common/modules/billing-metering/billing-metering.service';
import { GatewayService } from './gateway.service';
import { signZtRequest } from '../../common/crypto/hmac-signer';
import type { ZtConfig } from './types/zt-config.type';

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

function ensureMaxBodyBytes(body: Buffer, maxBytes: number): Buffer {
  if (body.length > maxBytes) throw new Error('Body too large');
  return body;
}

function readParsedBodyToBuffer(body: unknown, maxBytes: number): Buffer {
  if (body === undefined || body === null) {
    return Buffer.alloc(0);
  }

  if (Buffer.isBuffer(body)) {
    return ensureMaxBodyBytes(body, maxBytes);
  }

  if (body instanceof Uint8Array) {
    return ensureMaxBodyBytes(Buffer.from(body), maxBytes);
  }

  if (typeof body === 'string') {
    return ensureMaxBodyBytes(Buffer.from(body), maxBytes);
  }

  return ensureMaxBodyBytes(Buffer.from(JSON.stringify(body)), maxBytes);
}

function shouldForwardResponseHeader(name: string): boolean {
  const key = name.toLowerCase();

  return ![
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    'content-length',
  ].includes(key);
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

async function resolveReqBodyToBuffer(
  req: Request,
  maxBytes: number,
): Promise<Buffer> {
  if (typeof req.body !== 'undefined') {
    return readParsedBodyToBuffer(req.body, maxBytes);
  }

  return readReqBodyToBuffer(req, maxBytes);
}

@Controller('vault')
export class GatewayController {
  private readonly hmacSecret: string;

  constructor(
    private readonly gw: GatewayService,
    private readonly jwt: JwtVerifyService,
    private readonly policy: PolicyService,
    private readonly billingMetering: BillingMeteringService,
    cfg: ConfigService,
  ) {
    const zt = cfg.get<ZtConfig>('zt');
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

    const decision = await this.policy.decide({
      upstream: resolved.upstream.name,
      method: req.method,
      path: resolved.upstreamPath,
      tenantId: user.tenantId,
      roles: user.roles,
      actorType: user.actorType ?? 'user',
    });

    if (!decision.allow) {
      throw new ForbiddenException(
        'reason' in decision ? decision.reason : 'Policy denied request',
      );
    }

    const isApiClient = user.roles.includes('API_CLIENT');
    if (isApiClient && resolved.upstream.name === 'vault') {
      const metrics = ['vault_api_requests'];
      const upperMethod = req.method.toUpperCase();

      if (
        upperMethod === 'POST' &&
        resolved.upstreamPath === '/documents'
      ) {
        metrics.push('vault_api_upload_requests');
      }

      if (
        upperMethod === 'GET' &&
        /\/documents\/[^/]+\/download$/.test(resolved.upstreamPath)
      ) {
        metrics.push('vault_api_download_requests');
      }

      await Promise.all(
        metrics.map((metric) =>
          this.billingMetering.recordUsageEvent({
            tenantId: user.tenantId,
            addonCode: 'VAULT_API',
            metric,
            quantity: 1,
            sourceService: 'zerotrust-api',
            actorType: user.actorType ?? 'user',
            clientAppId: user.clientAppId,
            serviceAccountId: user.serviceAccountId,
            metadata: {
              method: upperMethod,
              path: resolved.upstreamPath,
            },
          }),
        ),
      );
    }

    // Bufferizamos body (MVP safe) para evitar problemas de types/streaming con undici
    const maxBodyBytes = 25 * 1024 * 1024; // 25MB
    const bodyBuf = isBodyless(req.method)
      ? Buffer.alloc(0)
      : await resolveReqBodyToBuffer(req, maxBodyBytes);

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

    // Respuesta como Buffer (evita Readable.fromWeb / pipeTo / casts)
    if (!upstreamRes.body) {
      res.end();
      return;
    }

    const ab = await upstreamRes.body.arrayBuffer();
    const out = Buffer.from(ab);

    for (const [k, v] of Object.entries(upstreamRes.headers)) {
      if (typeof v === 'string' && shouldForwardResponseHeader(k)) {
        res.setHeader(k, v);
      }
    }

    res.setHeader('content-length', String(out.length));
    res.send(out);
  }
}
