import type { Request } from 'express';
import { isLoopback } from './ip';

// Build a minimal Request. `ip` simulates what Express derives from
// X-Forwarded-For under `trust proxy`; `remoteAddress` is the real TCP peer.
function makeReq(opts: { remoteAddress?: string; forwardedIp?: string }): Request {
  return {
    socket: { remoteAddress: opts.remoteAddress },
    ip: opts.forwardedIp,
  } as unknown as Request;
}

describe('isLoopback', () => {
  it('accepts a genuine loopback peer', () => {
    expect(isLoopback(makeReq({ remoteAddress: '127.0.0.1' }))).toBe(true);
    expect(isLoopback(makeReq({ remoteAddress: '::1' }))).toBe(true);
    expect(isLoopback(makeReq({ remoteAddress: '::ffff:127.0.0.1' }))).toBe(true);
  });

  it('rejects a remote peer that spoofs X-Forwarded-For: 127.0.0.1', () => {
    // Real socket is public; only the (spoofable) forwarded ip claims loopback.
    expect(
      isLoopback(makeReq({ remoteAddress: '203.0.113.7', forwardedIp: '127.0.0.1' })),
    ).toBe(false);
  });

  it('rejects non-loopback and missing peers', () => {
    expect(isLoopback(makeReq({ remoteAddress: '10.0.0.5' }))).toBe(false);
    expect(isLoopback(makeReq({ remoteAddress: undefined }))).toBe(false);
  });
});
