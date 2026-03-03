import type { Request } from 'express';

export function isLoopback(req: Request): boolean {
  const ip = req.ip ?? '';
  // Express a veces trae ::ffff:127.0.0.1
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip === '::ffff:127.0.0.1' ||
    ip.startsWith('::ffff:127.')
  );
}
