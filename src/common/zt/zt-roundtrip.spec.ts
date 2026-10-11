import { signZt } from '../crypto/zt-v2-signer';
import { verifyZtRequest } from './zt-verify';

// Proves an upstream app (e.g. a customer service behind the gateway) can verify
// a request the ZT gateway signed — the trust boundary that lets any upstream
// adopt zero-trust verification, not just vault.
describe('ZT sign → verify round-trip (HMAC v1)', () => {
  const secret = 'test-shared-secret';
  const method = 'POST';
  const path = '/orders';
  const query = 'page=1';

  function sign() {
    return signZt(
      { mode: 'hmac', secret },
      {
        method,
        path,
        query,
        body: Buffer.from('{"item":1}'),
        userId: 'user-1',
        tenantId: 'tenant-1',
        roles: ['MEMBER'],
        tsMs: Date.now(),
        nonce: 'nonce-1',
      },
    );
  }

  it('verifies a freshly signed request', () => {
    const headers = sign();
    const result = verifyZtRequest({
      secret,
      method,
      path,
      query,
      headers,
      maxSkewMs: 30_000,
      replayCache: new Map(),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.tenantId).toBe('tenant-1');
      expect(result.roles).toEqual(['MEMBER']);
    }
  });

  it('rejects a tampered role claim', () => {
    const headers = sign();
    const tampered = { ...headers, 'x-zt-roles': 'OWNER' };
    const result = verifyZtRequest({
      secret,
      method,
      path,
      query,
      headers: tampered,
      maxSkewMs: 30_000,
      replayCache: new Map(),
    });
    expect(result.ok).toBe(false);
  });

  it('rejects a replayed nonce', () => {
    const headers = sign();
    const replayCache = new Map<string, number>();
    const args = {
      secret,
      method,
      path,
      query,
      headers,
      maxSkewMs: 30_000,
      replayCache,
    };
    expect(verifyZtRequest(args).ok).toBe(true);
    expect(verifyZtRequest(args).ok).toBe(false); // second use = replay
  });
});
