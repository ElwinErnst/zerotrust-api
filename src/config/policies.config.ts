import { registerAs } from '@nestjs/config';

export type PoliciesCfg = {
  filePath: string; // JSON local editable por Electron
};

export const policiesConfig = registerAs(
  'policies',
  (): PoliciesCfg => ({
    filePath: process.env.ZT_POLICIES_FILE ?? './local/policies.json',
  }),
);
