import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, createHmac, randomUUID } from 'crypto';
import type { BillingMeteringConfig } from './types/billing-metering-config.type';
import type { UsageEventPayload } from './types/usage-event-payload.type';

@Injectable()
export class BillingMeteringService {
  private readonly cfg: BillingMeteringConfig;

  constructor(private readonly configService: ConfigService) {
    this.cfg = this.configService.get<BillingMeteringConfig>('billingMetering')!;
  }

  async recordUsageEvent(payload: UsageEventPayload) {
    if (!this.cfg.baseUrl) {
      return;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.cfg.timeoutMs);

    try {
      const base = this.cfg.baseUrl.endsWith('/')
        ? this.cfg.baseUrl
        : `${this.cfg.baseUrl}/`;
      const url = new URL('internal/billing/usage-events', base);
      const body = JSON.stringify(payload);
      const headers = this.buildSignedHeaders('POST', url, body);

      const res = await fetch(url.toString(), {
        method: 'POST',
        headers: {
          ...headers,
          'content-type': 'application/json',
        },
        body,
        signal: controller.signal,
      });

      if (!res.ok) {
        console.warn(
          `billing metering rejected usage event with status ${res.status}`,
        );
      }
    } catch (error) {
      console.warn('billing metering request failed', error);
    } finally {
      clearTimeout(timeout);
    }
  }

  private buildSignedHeaders(
    method: string,
    url: URL,
    body: string,
  ): Record<string, string> {
    const ts = String(Date.now());
    const nonce = randomUUID();
    const bodySha256Hex = createHash('sha256').update(body).digest('hex');
    const canonical = [
      method.toUpperCase(),
      `${url.pathname}${url.search}`,
      bodySha256Hex,
      ts,
      nonce,
    ].join('\n');
    const signature = createHmac('sha256', this.cfg.hmacSecret)
      .update(canonical)
      .digest('hex');

    return {
      'x-internal-service-secret': this.cfg.serviceSecret,
      'x-internal-service-ts': ts,
      'x-internal-service-nonce': nonce,
      'x-internal-service-signature': signature,
    };
  }
}
