// Relay URL validation. Users choose which relays the watcher connects to, so
// a relay URL is attacker-controlled input: only public wss:// hosts are
// allowed, and the DNS lookup used for the socket rejects private/loopback
// addresses (the check happens at connect time, closing the DNS-rebinding gap
// a pre-check would leave).

import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from 'node:dns';
import { isIP, BlockList } from 'node:net';

const MAX_URL_LEN = 256;

// Separate lists: a BlockList checks IPv4 addresses against IPv6 rules as
// IPv4-mapped addresses, so one combined list would block all of IPv4.
const blocked4 = new BlockList();
const blocked6 = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blocked4.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['::ffff:0:0', 96], // IPv4-mapped (any form); DNS never needs these for a relay
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48], // RFC 8215 local-use IPv4/IPv6 translation
  ['fec0::', 10], // deprecated site-local
  ['100::', 64],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  blocked6.addSubnet(net, prefix, 'ipv6');
}

export function isPrivateAddress(addr: string): boolean {
  const fam = isIP(addr);
  if (fam === 0) return true;
  return fam === 4 ? blocked4.check(addr, 'ipv4') : blocked6.check(addr, 'ipv6');
}

const BLOCKED_SUFFIXES = ['.local', '.localhost', '.internal', '.lan', '.home', '.onion', '.home.arpa'];

/**
 * Normalise a relay URL, or return null if it is not acceptable.
 * `allowInsecure` (tests only) permits ws:// and private hosts.
 */
export function normalizeRelayUrl(input: unknown, allowInsecure = false): string | null {
  if (typeof input !== 'string' || input.length === 0 || input.length > MAX_URL_LEN) return null;
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    return null;
  }
  if (u.protocol !== 'wss:' && !(allowInsecure && u.protocol === 'ws:')) return null;
  if (u.username || u.password || u.search || u.hash) return null;
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return null;
  if (!allowInsecure) {
    const bare = host.replace(/^\[|\]$/g, '');
    if (isIP(bare) !== 0) return null; // no IP literals for user relays
    if (!host.includes('.')) return null;
    if (BLOCKED_SUFFIXES.some((s) => host.endsWith(s)) || host === 'localhost') return null;
  }
  const port = u.port ? `:${u.port}` : '';
  const path = u.pathname === '/' ? '' : u.pathname.replace(/\/+$/, '');
  return `${u.protocol}//${host}${port}${path}`;
}

type LookupCb = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/** dns.lookup replacement that refuses private/loopback/link-local results. */
export function safeLookup(hostname: string, options: LookupOptions, callback: LookupCb): void {
  dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, '');
    const list = addresses as LookupAddress[];
    const bad = list.find((a) => isPrivateAddress(a.address));
    if (bad || list.length === 0) {
      const e: NodeJS.ErrnoException = new Error(`relay host resolves to a non-public address`);
      e.code = 'EPRIVATEADDR';
      return callback(e, '');
    }
    if (options.all) return callback(null, list);
    const first = list[0]!;
    callback(null, first.address, first.family);
  });
}
