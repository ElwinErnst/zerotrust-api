import type { Request } from 'express';

/**
 * True only when the request's actual TCP peer is loopback.
 *
 * Uses `req.socket.remoteAddress` (the real transport peer) rather than
 * `req.ip`: under Express `trust proxy`, `req.ip` is derived from the
 * client-controlled `X-Forwarded-For` header, so a remote caller could send
 * `X-Forwarded-For: 127.0.0.1` to bypass admin-only ("local only") routes.
 * The socket peer address cannot be spoofed that way.
 */
export function isLoopback(req: Request): boolean {
  const ip = req.socket?.remoteAddress ?? '';
  // Express sometimes reports IPv4-mapped IPv6 like ::ffff:127.0.0.1
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip === '::ffff:127.0.0.1' ||
    ip.startsWith('::ffff:127.')
  );
}
