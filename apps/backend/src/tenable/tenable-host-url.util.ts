import * as dns from 'dns/promises';
import {isIP} from 'net';
import {HttpException, HttpStatus} from '@nestjs/common';

// Utilities for validating user-supplied Tenable host URLs before the backend
// makes any outbound request to them. This prevents Server-Side Request
// Forgery (SSRF) against internal services and cloud instance metadata
// endpoints (e.g. 169.254.169.254).

const IPV6_ZONE_REGEX = /%.*$/;
const IPV6_MAPPED_IPV4_REGEX = /^::ffff:(?<ipv4>\d+\.\d+\.\d+\.\d+)$/;
const IPV6_MAPPED_HEX_REGEX =
  /^::ffff:(?<high>[0-9a-f]{1,4}):(?<low>[0-9a-f]{1,4})$/;
const IPV6_LINK_LOCAL_REGEX = /^fe[89ab]/; // fe80::/10
const IPV6_UNIQUE_LOCAL_REGEX = /^f[cd]/; // fc00::/7
const IPV6_SITE_LOCAL_REGEX = /^fe[c-f]/; // fec0::/10

function invalidHostUrl(message: string): HttpException {
  return new HttpException(
    {
      status: HttpStatus.BAD_REQUEST,
      message,
      code: 'INVALID_HOST_URL'
    },
    HttpStatus.BAD_REQUEST
  );
}

const BLOCKED_IPV4_RANGES: Array<{base: string; prefix: number}> = [
  {base: '0.0.0.0', prefix: 8}, // "this network"
  {base: '10.0.0.0', prefix: 8}, // private
  {base: '100.64.0.0', prefix: 10}, // carrier-grade NAT
  {base: '127.0.0.0', prefix: 8}, // loopback
  {base: '169.254.0.0', prefix: 16}, // link-local / cloud metadata
  {base: '172.16.0.0', prefix: 12}, // private
  {base: '192.0.0.0', prefix: 24}, // IETF protocol assignments
  {base: '192.168.0.0', prefix: 16}, // private
  {base: '198.18.0.0', prefix: 15}, // benchmarking
  {base: '224.0.0.0', prefix: 3} // multicast + reserved (224.0.0.0-255.255.255.255)
];

function ipv4ToInt(ip: string): number {
  return (
    ip
      .split('.')
      .reduce((accumulator, octet) => accumulator * 256 + Number(octet), 0) >>>
    0
  );
}

function isBlockedIpv4(ip: string): boolean {
  const ipInt = ipv4ToInt(ip);
  return BLOCKED_IPV4_RANGES.some(({base, prefix}) => {
    const shift = 32 - prefix;
    return ipInt >>> shift === ipv4ToInt(base) >>> shift;
  });
}

function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(IPV6_ZONE_REGEX, '');
  if (lower === '::' || lower === '::1') {
    return true; // unspecified / loopback
  }
  const mappedIpv4 = IPV6_MAPPED_IPV4_REGEX.exec(lower);
  if (mappedIpv4?.groups) {
    return isBlockedIpv4(mappedIpv4.groups.ipv4);
  }
  // IPv4-mapped in hex form, e.g. ::ffff:a9fe:a9fe (produced by URL parsing)
  const mappedHex = IPV6_MAPPED_HEX_REGEX.exec(lower);
  if (mappedHex?.groups) {
    const high = Number.parseInt(mappedHex.groups.high, 16);
    const low = Number.parseInt(mappedHex.groups.low, 16);
    return isBlockedIpv4(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
  }
  return (
    IPV6_LINK_LOCAL_REGEX.test(lower) ||
    IPV6_UNIQUE_LOCAL_REGEX.test(lower) ||
    IPV6_SITE_LOCAL_REGEX.test(lower)
  );
}

export function isBlockedAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) {
    return isBlockedIpv4(address);
  }
  if (version === 6) {
    return isBlockedIpv6(address);
  }
  return true;
}

/**
 * Validates a Tenable host URL before any outbound request is made to it.
 *
 * If an operator-configured host URL is provided (TENABLE_HOST_URL), the
 * supplied URL must match its origin exactly. Otherwise the URL must use
 * https and must not resolve to a loopback, private, link-local, or
 * otherwise reserved address.
 *
 * @param hostUrl - The host URL supplied by the client.
 * @param configuredHostUrl - The operator-configured Tenable host URL, if any.
 * @returns The normalized origin (scheme://host[:port]) to use for requests.
 * @throws {HttpException} 400 if the URL fails validation.
 */
export async function validateTenableHostUrl(
  hostUrl: string,
  configuredHostUrl?: string
): Promise<string> {
  let parsed: URL;
  try {
    parsed = new URL(hostUrl);
  } catch {
    throw invalidHostUrl('Tenable host URL is not a valid URL');
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw invalidHostUrl('Tenable host URL must use http or https');
  }

  if (
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.pathname !== '/' && parsed.pathname !== '')
  ) {
    throw invalidHostUrl(
      'Tenable host URL must not contain a path, query, fragment, or embedded credentials'
    );
  }

  if (configuredHostUrl) {
    let configured: URL;
    try {
      configured = new URL(configuredHostUrl);
    } catch {
      throw invalidHostUrl('The configured TENABLE_HOST_URL is not a valid URL');
    }
    if (parsed.origin !== configured.origin) {
      throw invalidHostUrl(
        'Tenable host URL does not match the configured Tenable host'
      );
    }
    return parsed.origin;
  }

  if (parsed.protocol !== 'https:') {
    throw invalidHostUrl('Tenable host URL must use https');
  }

  // URL.hostname returns IPv6 literals without brackets
  const hostname = parsed.hostname;
  let addresses: string[];
  if (isIP(hostname)) {
    addresses = [hostname];
  } else {
    try {
      const results = await dns.lookup(hostname, {all: true});
      addresses = results.map((result) => result.address);
    } catch {
      throw invalidHostUrl('Unable to resolve Tenable host URL to an IP address');
    }
  }

  if (
    addresses.length === 0 ||
    addresses.some((address) => isBlockedAddress(address))
  ) {
    throw invalidHostUrl(
      'Tenable host URL resolves to a loopback, private, link-local, or reserved address'
    );
  }

  return parsed.origin;
}
