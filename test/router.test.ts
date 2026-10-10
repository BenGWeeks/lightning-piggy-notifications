import { describe, expect, it } from 'vitest';
import type { NostrEvent } from 'nostr-tools/pure';
import { reasonCode, relayLabel, setPublicRelays } from '../src/relay.js';
import { isPrivateAddress, normalizeRelayUrl } from '../src/relayUrl.js';
import { RouteIndex, SeenCache } from '../src/router.js';
import type { RegistrationSummary } from '../src/store.js';

const U = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);
const NWC = 'c'.repeat(64);
const WALLET = 'e'.repeat(64);
const reg = (over: Partial<RegistrationSummary> = {}): RegistrationSummary => ({
  user: U,
  tokenHash: 't',
  app: 'com.lightningpiggy.app',
  platform: 'fcm',
  categories: { dm: true, zap: true, mention: true, payment: true },
  relays: [],
  nwc: [{ client: NWC, wallet: WALLET }],
  ...over,
});
const ev = (kind: number, pubkey: string, tags: string[][]): NostrEvent =>
  ({ id: '0'.repeat(64), pubkey, created_at: 0, kind, tags, content: '', sig: '' }) as NostrEvent;

describe('RouteIndex', () => {
  const idx = new RouteIndex([reg()]);

  it('routes each kind to its category', () => {
    expect(idx.route(ev(4, OTHER, [['p', U]]))).toEqual([{ user: U, category: 'dm' }]);
    expect(idx.route(ev(1059, OTHER, [['p', U]]))).toEqual([{ user: U, category: 'dm' }]);
    expect(idx.route(ev(1, OTHER, [['p', U]]))).toEqual([{ user: U, category: 'mention' }]);
    expect(idx.route(ev(9735, OTHER, [['p', U], ['P', OTHER]]))).toEqual([{ user: U, category: 'zap' }]);
    expect(idx.route(ev(23196, WALLET, [['p', NWC]]))).toEqual([{ user: U, category: 'payment' }]);
    expect(idx.route(ev(23197, WALLET, [['p', U]]))).toEqual([]); // user pubkey isn't an NWC client key
    expect(idx.route(ev(23197, OTHER, [['p', NWC]]))).toEqual([]); // only the registered wallet may trigger
  });

  it("ignores the user's own events", () => {
    expect(idx.route(ev(4, U, [['p', U]]))).toEqual([]);
    expect(idx.route(ev(1, U, [['p', U]]))).toEqual([]);
    expect(idx.route(ev(9735, OTHER, [['p', U], ['P', U]]))).toEqual([]); // self-zap
  });

  it('respects categories and unknown users', () => {
    const off = new RouteIndex([reg({ categories: { dm: false, zap: true, mention: false, payment: false } })]);
    expect(off.route(ev(4, OTHER, [['p', U]]))).toEqual([]);
    expect(off.route(ev(1, OTHER, [['p', U]]))).toEqual([]);
    expect(off.route(ev(23196, WALLET, [['p', NWC]]))).toEqual([]);
    expect(idx.route(ev(4, OTHER, [['p', OTHER]]))).toEqual([]);
  });

  it('caps owners per NWC client key', () => {
    const regs = Array.from({ length: 10 }, (_, i) => reg({ user: i.toString(16).padStart(64, '0') }));
    expect(new RouteIndex(regs, 3).route(ev(23196, WALLET, [['p', NWC]]))).toHaveLength(3);
  });

  it('dedupes repeated p-tags', () => {
    expect(idx.route(ev(1, OTHER, [['p', U], ['p', U]]))).toHaveLength(1);
  });
});

describe('SeenCache', () => {
  it('dedupes and evicts oldest past the bound', () => {
    const s = new SeenCache(2);
    s.add('a');
    s.add('b');
    s.add('a');
    expect(s.has('a')).toBe(true);
    s.add('c');
    expect(s.has('a')).toBe(false);
    expect(s.has('c')).toBe(true);
    expect(s.size).toBe(2);
  });
});

describe('relay URL validation', () => {
  it('normalises and rejects unsafe relays', () => {
    expect(normalizeRelayUrl('wss://Relay.Damus.io/')).toBe('wss://relay.damus.io');
    expect(normalizeRelayUrl('wss://nos.lol:443/inbox/')).toBe('wss://nos.lol/inbox');
    expect(normalizeRelayUrl('wss://nos.lol:7777')).toBe('wss://nos.lol:7777');
    for (const bad of [
      'ws://relay.damus.io',
      'https://relay.damus.io',
      'wss://127.0.0.1',
      'wss://[::1]',
      'wss://localhost',
      'wss://printer.local',
      'wss://intranet',
      'wss://u:p@relay.example.com',
      'wss://relay.example.com/?x=1',
      `wss://${'a'.repeat(300)}.com`,
      42,
    ]) {
      expect(normalizeRelayUrl(bad)).toBeNull();
    }
    expect(normalizeRelayUrl('ws://127.0.0.1:7777', true)).toBe('ws://127.0.0.1:7777');
  });

  it('extracts only the machine-readable reason code', () => {
    expect(reasonCode('auth-required: please authenticate')).toBe('auth-required');
    expect(reasonCode('ERROR: auth-required: requested filter requires authentication')).toBe('auth-required');
    expect(reasonCode('banned: too many rate-limit violations, try again later')).toBe('banned');
    expect(reasonCode('npub1abc… is not allowed')).toBe('other');
    expect(reasonCode(undefined)).toBe('other');
  });

  it('logs configured relays by host and user relays opaquely', () => {
    setPublicRelays(['wss://nos.lol']);
    expect(relayLabel('wss://nos.lol')).toBe('nos.lol');
    expect(relayLabel('wss://npub1secretish.example.com/abc')).toMatch(/^user-relay:[0-9a-f]{10}$/);
  });

  it('safeLookup refuses hostnames resolving to private addresses', async () => {
    const { safeLookup } = await import('../src/relayUrl.js');
    const err = await new Promise<NodeJS.ErrnoException | null>((r) => safeLookup('localhost', {}, (e) => r(e)));
    expect(err?.code).toBe('EPRIVATEADDR');
  });

  it('classifies private addresses', () => {
    for (const a of ['127.0.0.1', '10.1.2.3', '192.168.1.1', '172.20.0.1', '169.254.1.1', '::1', 'fd00::1', 'fe80::1', 'fec0::1', '64:ff9b:1::a00:1', '::ffff:10.0.0.1', '::ffff:1.1.1.1', '::ffff:a00:1']) {
      expect(isPrivateAddress(a)).toBe(true);
    }
    for (const a of ['1.1.1.1', '8.8.8.8', '2606:4700::1111']) expect(isPrivateAddress(a)).toBe(false);
  });
});
