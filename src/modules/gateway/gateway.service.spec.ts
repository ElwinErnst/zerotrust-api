import type { Request } from 'express';
import { GatewayService } from './gateway.service';

function makeReq(originalUrl: string): Request {
  return { originalUrl } as unknown as Request;
}

describe('GatewayService', () => {
  const cfg = {
    get: jest.fn(),
  };
  const admin = {
    getUpstreams: jest.fn(),
  };

  function build(registered: Array<Record<string, string>> = []): GatewayService {
    cfg.get.mockReturnValue({
      upstreams: [
        { name: 'vault', baseUrl: 'http://vault:3000', matchPrefix: '/vault' },
      ],
    });
    admin.getUpstreams.mockReturnValue({ version: 1, upstreams: registered });
    return new GatewayService(cfg as never, admin as never);
  }

  beforeEach(() => jest.resetAllMocks());

  it('routes the built-in vault upstream and strips its prefix', () => {
    const gw = build();
    const resolved = gw.resolve(makeReq('/vault/documents?x=1'));
    expect(resolved?.upstream.name).toBe('vault');
    expect(resolved?.upstreamPath).toBe('/documents');
  });

  it('routes a file-registered upstream under the /gw namespace', () => {
    const gw = build([
      { name: 'myapp', baseUrl: 'https://api.myapp.com', matchPrefix: '/gw/myapp' },
    ]);
    const resolved = gw.resolve(makeReq('/gw/myapp/orders/42'));
    expect(resolved?.upstream.name).toBe('myapp');
    expect(resolved?.upstreamPath).toBe('/orders/42');
  });

  it('ignores a registered upstream whose prefix is outside /gw (cannot hijack routes)', () => {
    const gw = build([
      { name: 'evil', baseUrl: 'https://evil.com', matchPrefix: '/vault' },
    ]);
    // /vault still resolves to the built-in vault, not the impostor.
    expect(gw.resolve(makeReq('/vault/x'))?.upstream.baseUrl).toBe(
      'http://vault:3000',
    );
  });

  it('ignores a registered upstream reusing a built-in name', () => {
    const gw = build([
      { name: 'vault', baseUrl: 'https://evil.com', matchPrefix: '/gw/vault' },
    ]);
    expect(gw.resolve(makeReq('/gw/vault/x'))).toBeNull();
  });

  it('returns null when no upstream matches', () => {
    const gw = build();
    expect(gw.resolve(makeReq('/nope'))).toBeNull();
  });

  it('reports built-in membership', () => {
    const gw = build();
    expect(gw.isBuiltin('vault')).toBe(true);
    expect(gw.isBuiltin('myapp')).toBe(false);
  });

  it('keeps routing the built-in vault when the file registry read throws', () => {
    // A failure reading the untrusted registry must not break the vault route.
    const gw = build();
    admin.getUpstreams.mockImplementation(() => {
      throw new Error('registry unavailable');
    });
    const resolved = gw.resolve(makeReq('/vault/documents'));
    expect(resolved?.upstream.name).toBe('vault');
    expect(resolved?.upstreamPath).toBe('/documents');
  });
});
