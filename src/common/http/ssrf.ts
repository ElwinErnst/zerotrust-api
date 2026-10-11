import { lookup } from 'dns/promises';
import { isIP } from 'net';

/**
 * Raised when a forward target resolves to an address the gateway refuses to
 * reach. Applied to untrusted (file-registered) upstream URLs before connecting,
 * so a tenant-controlled base URL cannot be pointed at internal infrastructure
 * or cloud metadata (SSRF).
 */
export class SsrfBlockedError extends Error {}

export function isBlockedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isBlockedIpv4(ip);
  if (version === 6) return isBlockedIpv6(ip);
  return true; // not a parseable IP → block defensively
}

function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => Number(p));
  if (
    parts.length !== 4 ||
    parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)
  ) {
    return true;
  }
  const [a, b] = parts;
  if (a === 0) return true; // "this" network 0.0.0.0/8
  if (a === 10) return true; // private 10.0.0.0/8
  if (a === 127) return true; // loopback 127.0.0.0/8
  if (a === 169 && b === 254) return true; // link-local incl. metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // private 172.16.0.0/12
  if (a === 192 && b === 168) return true; // private 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a >= 224) return true; // multicast / reserved
  return false;
}

function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true; // unspecified / loopback
  if (lower.startsWith('fe80')) return true; // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA fc00::/7
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower); // IPv4-mapped
  if (mapped) return isBlockedIpv4(mapped[1]);
  return false;
}

/**
 * Validate that `rawUrl` is a public http(s) endpoint. Resolves every A/AAAA
 * record and rejects if ANY resolves to a blocked range — a basic DNS-rebind
 * defense: we validate what the connection would actually reach.
 */
export async function assertUpstreamUrlSafe(rawUrl: string): Promise<void> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfBlockedError('Invalid upstream URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfBlockedError(`Blocked upstream protocol: ${url.protocol}`);
  }

  const host = url.hostname;
  const addresses = isIP(host)
    ? [host]
    : await resolveHost(host);

  if (addresses.length === 0) {
    throw new SsrfBlockedError(`No addresses for host: ${host}`);
  }

  for (const address of addresses) {
    if (isBlockedIp(address)) {
      throw new SsrfBlockedError(
        `Blocked upstream address ${address} for host ${host}`,
      );
    }
  }
}

async function resolveHost(host: string): Promise<string[]> {
  try {
    const records = await lookup(host, { all: true });
    return records.map((r) => r.address);
  } catch {
    throw new SsrfBlockedError(`Cannot resolve upstream host: ${host}`);
  }
}
