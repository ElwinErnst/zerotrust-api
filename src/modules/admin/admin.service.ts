import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { readFile } from 'fs/promises';
import {
  PoliciesFile,
  PoliciesFileSchema,
  UpstreamsFile,
  UpstreamsFileSchema,
} from './types';
import type { PoliciesConfig } from './types/policies-config.type';
import type { UpstreamsConfig } from './types/upstreams-config.type';

@Injectable()
export class AdminService {
  private policies: PoliciesFile = { version: 1, rules: [] };
  private upstreams: UpstreamsFile = { version: 1, upstreams: [] };

  constructor(private readonly cfg: ConfigService) {}

  getPolicies(): PoliciesFile {
    return this.policies;
  }

  getUpstreams(): UpstreamsFile {
    return this.upstreams;
  }

  getStatus(): {
    policiesRules: number;
    upstreams: number;
  } {
    return {
      policiesRules: this.policies.rules.length,
      upstreams: this.upstreams.upstreams.length,
    };
  }

  async loadAll(): Promise<void> {
    this.policies = await this.loadPoliciesFromFile();
    this.upstreams = await this.loadUpstreamsFromFile();
  }

  private async loadPoliciesFromFile(): Promise<PoliciesFile> {
    const p = this.cfg.get<PoliciesConfig>('policies');
    if (!p?.filePath) return { version: 1, rules: [] };

    const raw = await readFile(p.filePath, 'utf8');
    const parsedUnknown: unknown = JSON.parse(raw);

    const validated = PoliciesFileSchema.safeParse(parsedUnknown);
    if (!validated.success) {
      throw new Error(`Invalid policies file: ${validated.error.message}`);
    }

    // Normalizamos method a upper en el PolicyService (no acá)
    return validated.data;
  }

  private async loadUpstreamsFromFile(): Promise<UpstreamsFile> {
    // tu proyecto ya tiene upstreams.config.ts: si querés “solo archivo”, agregá ZT_UPSTREAMS_FILE
    const p = this.cfg.get<UpstreamsConfig>('upstreams');

    // Prioridad: archivo si está configurado
    const filePath =
      typeof p?.filePath === 'string'
        ? p.filePath
        : process.env.ZT_UPSTREAMS_FILE;
    if (filePath) {
      const raw = await readFile(filePath, 'utf8');
      const parsedUnknown: unknown = JSON.parse(raw);

      const validated = UpstreamsFileSchema.safeParse(parsedUnknown);
      if (!validated.success) {
        throw new Error(`Invalid upstreams file: ${validated.error.message}`);
      }
      return validated.data;
    }

    // Fallback: upstreams desde config (si tu upstreams.config.ts ya lo provee)
    const validated = UpstreamsFileSchema.safeParse(p);
    if (!validated.success) {
      return { version: 1, upstreams: [] };
    }

    return validated.data;
  }
}
