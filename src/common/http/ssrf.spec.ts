import { lookup } from 'dns/promises';
import { assertUpstreamUrlSafe, isBlockedIp, SsrfBlockedError } from './ssrf';

jest.mock('dns/promises', () => ({ lookup: jest.fn() }));

const lookupMock = lookup as unknown as jest.Mock;

describe('isBlockedIp', () => {
  it.each([
    '169.254.169.254', // cloud metadata
    '127.0.0.1', // loopback
    '10.1.2.3', // private
    '172.16.5.5', // private
    '192.168.0.10', // private
    '100.64.0.1', // CGNAT
    '0.0.0.0', // unspecified
    '::1', // ipv6 loopback
    'fe80::1', // ipv6 link-local
    'fd00::1', // ipv6 ULA
    'not-an-ip',
  ])('blocks %s', (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34'])('allows public %s', (ip) => {
    expect(isBlockedIp(ip)).toBe(false);
  });
});

describe('assertUpstreamUrlSafe', () => {
  beforeEach(() => lookupMock.mockReset());

  it('rejects the cloud metadata address', async () => {
    await expect(
      assertUpstreamUrlSafe('http://169.254.169.254/latest/meta-data'),
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('rejects loopback and private hosts', async () => {
    await expect(assertUpstreamUrlSafe('http://127.0.0.1:3000')).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
    await expect(assertUpstreamUrlSafe('http://10.0.0.5')).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('rejects non-http(s) protocols', async () => {
    await expect(assertUpstreamUrlSafe('file:///etc/passwd')).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('returns the address for a public IP literal (no DNS lookup)', async () => {
    await expect(assertUpstreamUrlSafe('https://8.8.8.8/health')).resolves.toEqual([
      '8.8.8.8',
    ]);
    expect(lookupMock).not.toHaveBeenCalled();
  });

  // --- hostname / DNS resolution path (the DNS-rebind defense) ---

  it('resolves a hostname and returns its validated public addresses', async () => {
    lookupMock.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    await expect(assertUpstreamUrlSafe('https://example.com/api')).resolves.toEqual([
      '93.184.216.34',
    ]);
    expect(lookupMock).toHaveBeenCalledWith('example.com', { all: true });
  });

  it('rejects a hostname that resolves to a blocked (internal) address', async () => {
    lookupMock.mockResolvedValue([{ address: '169.254.169.254', family: 4 }]);
    await expect(assertUpstreamUrlSafe('https://rebind.evil/')).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('rejects if ANY resolved address is blocked (mixed records)', async () => {
    lookupMock.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.5', family: 4 },
    ]);
    await expect(assertUpstreamUrlSafe('https://split.evil/')).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('rejects when the host cannot be resolved', async () => {
    lookupMock.mockRejectedValue(new Error('ENOTFOUND'));
    await expect(assertUpstreamUrlSafe('https://nope.invalid/')).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('rejects when resolution yields no addresses', async () => {
    lookupMock.mockResolvedValue([]);
    await expect(assertUpstreamUrlSafe('https://empty.example/')).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });
});
