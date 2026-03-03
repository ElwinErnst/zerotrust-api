import { registerAs } from '@nestjs/config';

export default registerAs('zt', () => ({
  hmacSecret: process.env.ZT_HMAC_SECRET ?? 'zt-hmac-secret-change-me',
}));
