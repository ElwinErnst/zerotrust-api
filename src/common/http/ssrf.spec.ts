import { assertUpstreamUrlSafe, isBlockedIp, SsrfBlockedError } from './ssrf';

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

  it('allows a public IP literal', async () => {
    await expect(assertUpstreamUrlSafe('https://8.8.8.8/health')).resolves.toBeUndefined();
  });
});
