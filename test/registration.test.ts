import { describe, expect, it } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import { createWrap } from 'nostr-tools/nip59';
import { encrypt as nip44Encrypt, getConversationKey } from 'nostr-tools/nip44';
import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, type NostrEvent } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { DEFAULT_LIMITS } from '../src/config.js';
import {
  nwcProofMessage,
  parseRegistration,
  REGISTRATION_KIND,
  RegistrationError,
  unwrapRegistration,
  type RegistrationRequest,
} from '../src/registration.js';
import { Store } from '../src/store.js';
import { APNS_TOKEN, FCM_TOKEN, makeRegistrationWrap, regContent } from './helpers.js';

const watcherSk = generateSecretKey();
const watcherPk = getPublicKey(watcherSk);
const userSk = generateSecretKey();
const userPk = getPublicKey(userSk);
const apps = ['com.lightningpiggy.app', 'com.lightningpiggy.app.preview'];
const nowSec = Math.floor(Date.now() / 1000);

function parse(content: Record<string, unknown>, opts: { now?: number } = {}): RegistrationRequest {
  const wrap = makeRegistrationWrap(userSk, watcherPk, content);
  const { rumor } = unwrapRegistration(wrap, watcherSk);
  return parseRegistration(rumor, { apps, limits: DEFAULT_LIMITS, allowInsecureRelays: false, nowSec: opts.now ?? nowSec });
}

function reason(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof RegistrationError) return e.reason;
    throw e;
  }
  return 'no error';
}

describe('unwrapRegistration', () => {
  it('authenticates the user via the seal signature', () => {
    const wrap = makeRegistrationWrap(userSk, watcherPk, regContent());
    const { rumor, sealPubkey } = unwrapRegistration(wrap, watcherSk);
    expect(sealPubkey).toBe(userPk);
    expect(rumor.pubkey).toBe(userPk);
  });

  it('rejects a seal with a bad signature', () => {
    const wrap = makeRegistrationWrap(userSk, watcherPk, regContent(), {
      tamperSeal: (s: NostrEvent) => ({ ...s, sig: s.sig.replace(/^./, (c) => (c === '0' ? '1' : '0')) }),
    });
    expect(reason(() => unwrapRegistration(wrap, watcherSk))).toBe('seal signature invalid');
  });

  /** Hand-build a wrap so individual layers can be forged. */
  function forge(opts: { rumorPubkey: string; sealSk: Uint8Array; mutateRumor?: (r: NostrEvent) => void; sealTags?: string[][] }) {
    const content = JSON.stringify(regContent());
    const ts = JSON.parse(content).ts as number;
    const rumor = { kind: REGISTRATION_KIND, pubkey: opts.rumorPubkey, created_at: ts, tags: [] as string[][], content } as NostrEvent;
    rumor.id = getEventHash(rumor);
    opts.mutateRumor?.(rumor);
    const seal = finalizeEvent(
      { kind: 13, created_at: ts, tags: opts.sealTags ?? [], content: nip44Encrypt(JSON.stringify(rumor), getConversationKey(opts.sealSk, watcherPk)) },
      opts.sealSk,
    );
    return createWrap(seal, watcherPk);
  }

  it("rejects an attacker-signed seal around the victim's rumor", () => {
    const wrap = forge({ rumorPubkey: userPk, sealSk: generateSecretKey() });
    expect(reason(() => unwrapRegistration(wrap, watcherSk))).toBe('rumor pubkey does not match seal signer');
  });

  it('rejects a rumor whose id is not its hash, and seals with tags', () => {
    expect(reason(() => unwrapRegistration(forge({ rumorPubkey: userPk, sealSk: userSk, mutateRumor: (r) => (r.content += ' ') }), watcherSk))).toBe(
      'rumor id mismatch',
    );
    expect(reason(() => unwrapRegistration(forge({ rumorPubkey: userPk, sealSk: userSk, sealTags: [['p', watcherPk]] }), watcherSk))).toBe(
      'seal must have no tags',
    );
    expect(unwrapRegistration(forge({ rumorPubkey: userPk, sealSk: userSk }), watcherSk).sealPubkey).toBe(userPk);
  });

  it('rejects wraps not addressed to the watcher', () => {
    const wrap = makeRegistrationWrap(userSk, getPublicKey(generateSecretKey()), regContent());
    expect(reason(() => unwrapRegistration(wrap, watcherSk))).toBe('wrap decrypt failed');
  });

  it('rejects non-gift-wrap kinds and oversized content', () => {
    const wrap = makeRegistrationWrap(userSk, watcherPk, regContent());
    expect(reason(() => unwrapRegistration({ ...wrap, kind: 1 }, watcherSk))).toBe('not a gift wrap');
    expect(reason(() => unwrapRegistration({ ...wrap, content: 'x'.repeat(100_000) }, watcherSk))).toBe('wrap too large');
  });
});

describe('parseRegistration', () => {
  it('parses a valid registration', () => {
    const r = parse(regContent({ relays: ['wss://Relay.Example.com/', 'ws://insecure.example.com', 'wss://10.0.0.1'] }));
    expect(r.user).toBe(userPk);
    expect(r.action).toBe('register');
    expect(r.relays).toEqual(['wss://relay.example.com']);
    expect(r.categories).toEqual({ dm: true, zap: true, mention: true, payment: true });
  });

  it('enforces the timestamp window', () => {
    expect(reason(() => parse(regContent({}, nowSec - 7 * 3600)))).toBe('registration too old');
    expect(reason(() => parse(regContent({}, nowSec + 3600)))).toBe('registration from the future');
  });

  it('requires ts to equal the rumor created_at', () => {
    const content = regContent();
    const wrap = makeRegistrationWrap(userSk, watcherPk, content);
    const { rumor } = unwrapRegistration(wrap, watcherSk);
    const forged = { ...rumor, created_at: rumor.created_at - 1 };
    expect(reason(() => parseRegistration(forged, { apps, limits: DEFAULT_LIMITS, allowInsecureRelays: false, nowSec }))).toBe(
      'ts must equal rumor created_at',
    );
  });

  it('rejects unknown apps, bad tokens and bad platforms', () => {
    expect(reason(() => parse(regContent({ app: 'com.evil.app' })))).toBe('unknown app');
    expect(reason(() => parse(regContent({ platform: 'apns', token: 'xyz' })))).toBe('bad token');
    expect(reason(() => parse(regContent({ token: 'short' })))).toBe('bad token');
    expect(reason(() => parse(regContent({ platform: 'webpush' })))).toBe('bad platform');
    expect(parse(regContent({ platform: 'apns', token: APNS_TOKEN })).platform).toBe('apns');
  });

  it('bounds relays', () => {
    const many = Array.from({ length: 12 }, (_, i) => `wss://r${i}.example.com`);
    expect(parse(regContent({ relays: many })).relays).toHaveLength(DEFAULT_LIMITS.maxRelaysPerRegistration);
    expect(reason(() => parse(regContent({ relays: [...many, ...many] })))).toBe('too many relays');
  });

  describe('NWC connections', () => {
    const clientSk = generateSecretKey();
    const client = getPublicKey(clientSk);
    const wallet = getPublicKey(generateSecretKey());
    const proof = (user = userPk, w = wallet, sk = clientSk) => bytesToHex(schnorr.sign(nwcProofMessage(user, w), sk));

    it('accepts a connection proven by the NWC client key', () => {
      expect(parse(regContent({ nwc: [{ client, wallet, proof: proof() }] })).nwc).toEqual([{ client, wallet }]);
    });

    it('rejects claims without a valid proof', () => {
      const other = getPublicKey(generateSecretKey());
      expect(reason(() => parse(regContent({ nwc: [{ client, wallet, proof: proof(other) }] })))).toBe('nwc proof invalid'); // bound to another user
      expect(reason(() => parse(regContent({ nwc: [{ client, wallet: other, proof: proof() }] })))).toBe('nwc proof invalid'); // different wallet
      expect(reason(() => parse(regContent({ nwc: [{ client, wallet, proof: proof(userPk, wallet, generateSecretKey()) }] })))).toBe(
        'nwc proof invalid',
      );
      expect(reason(() => parse(regContent({ nwc: [{ client: 'nothex', wallet, proof: proof() }] })))).toBe('bad nwc client pubkey');
      const nine = Array.from({ length: 9 }, () => ({ client, wallet, proof: proof() }));
      expect(reason(() => parse(regContent({ nwc: nine })))).toBe('bad nwc');
    });
  });

  it('rejects the wrong rumor kind and version', () => {
    const wrap = makeRegistrationWrap(userSk, watcherPk, regContent(), { kind: 14 });
    const { rumor } = unwrapRegistration(wrap, watcherSk);
    expect(reason(() => parseRegistration(rumor, { apps, limits: DEFAULT_LIMITS, allowInsecureRelays: false, nowSec }))).toMatch(
      /unexpected rumor kind/,
    );
    expect(reason(() => parse(regContent({ v: 2 })))).toBe('unsupported version');
  });
});

describe('Store replay protection', () => {
  const store = () => new Store(':memory:', Buffer.alloc(32, 1), DEFAULT_LIMITS);

  it('newest wins per (user, token); replays and older registrations are stale', () => {
    const s = store();
    const r1 = parse(regContent({}, nowSec - 10));
    expect(s.apply(r1, nowSec)).toBe('registered');
    expect(s.apply(r1, nowSec)).toBe('stale'); // exact replay
    const r2 = parse(regContent({ categories: { dm: true } }, nowSec - 5));
    expect(s.apply(r2, nowSec)).toBe('updated');
    expect(s.apply(r1, nowSec)).toBe('stale'); // older replay can't roll back
    expect(s.listActive()[0]!.categories).toEqual({ dm: true, zap: false, mention: false, payment: false });
  });

  it('unregister removes the device and blocks replayed registrations', () => {
    const s = store();
    const reg = parse(regContent({}, nowSec - 10));
    s.apply(reg, nowSec);
    const unreg = parse(regContent({ action: 'unregister' }, nowSec - 5));
    expect(s.apply(unreg, nowSec)).toBe('unregistered');
    expect(s.countActive()).toBe(0);
    expect(s.apply(reg, nowSec)).toBe('stale');
    expect(s.devicesFor(userPk)).toEqual([]);
  });

  it('encrypts tokens at rest and decrypts them for delivery', () => {
    const s = store();
    s.apply(parse(regContent()), nowSec);
    const devices = s.devicesFor(userPk);
    expect(devices[0]!.token).toBe(FCM_TOKEN);
    // A store opened with a different key can't read the token.
    const db = (s as unknown as { db: { prepare: (q: string) => { get: () => { token_enc: Buffer } } } }).db;
    const blob = db.prepare('SELECT token_enc FROM registrations').get().token_enc;
    expect(blob.includes(Buffer.from(FCM_TOKEN))).toBe(false);
  });

  it('caps devices per user and expires unrefreshed registrations', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), { ...DEFAULT_LIMITS, maxDevicesPerUser: 2 });
    for (let i = 0; i < 3; i++) {
      s.apply(parse(regContent({ token: `${FCM_TOKEN}${i}` }, nowSec - 10 + i)), nowSec + i);
    }
    expect(s.countActive()).toBe(2);
    // The evicted device can't be brought back by replaying its registration.
    expect(s.isStale(parse(regContent({ token: `${FCM_TOKEN}0` }, nowSec - 10)))).toBe(true);
    const later = nowSec + DEFAULT_LIMITS.registrationTtlDays * 86400 + 10;
    expect(s.sweep(later).expired).toBe(2);
  });

  it('removeRegistration only removes the exact registration version that was sent', () => {
    const s = store();
    s.apply(parse(regContent({}, nowSec - 10)), nowSec);
    const [d] = s.devicesFor(userPk);
    s.apply(parse(regContent({}, nowSec - 5)), nowSec); // refreshed meanwhile
    expect(s.removeRegistration(d!.user, d!.tokenHash, d!.ts)).toBe(false);
    expect(s.countActive()).toBe(1);
    const [d2] = s.devicesFor(userPk);
    expect(s.removeRegistration(d2!.user, d2!.tokenHash, d2!.ts)).toBe(true);
    expect(s.countActive()).toBe(0);
  });

  it('scopes tokens by app: one app id cannot affect another', () => {
    const s = store();
    expect(s.tokenHash('apns', 'com.lightningpiggy.app', APNS_TOKEN)).not.toBe(s.tokenHash('apns', 'com.lightningpiggy.app.preview', APNS_TOKEN));
  });

  it('canonicalises APNs token case so variants are one device', () => {
    const s = store();
    const lower = parse(regContent({ platform: 'apns', token: 'ab'.repeat(32) }, nowSec - 10));
    expect(s.apply(lower, nowSec)).toBe('registered');
    const upper = parse(regContent({ platform: 'apns', token: 'AB'.repeat(32), action: 'unregister' }, nowSec - 5));
    expect(upper.token).toBe('ab'.repeat(32));
    expect(s.apply(upper, nowSec)).toBe('unregistered');
    expect(s.countActive()).toBe(0);
  });

  it('an unregister for an unknown device blocks its older register (out-of-order delivery)', () => {
    const s = store();
    expect(s.apply(parse(regContent({ token: `${FCM_TOKEN}y`, action: 'unregister' }, nowSec - 10)), nowSec)).toBe('unregistered');
    expect(s.countActive()).toBe(0);
    expect(s.apply(parse(regContent({ token: `${FCM_TOKEN}y` }, nowSec - 20)), nowSec)).toBe('stale');
    expect(s.apply(parse(regContent({ token: `${FCM_TOKEN}y` }, nowSec - 5)), nowSec)).toBe('registered');
  });

  it("one user's future-dated unregisters never affect other users", () => {
    const s = store();
    const attackerSk = generateSecretKey();
    const { rumor } = unwrapRegistration(
      makeRegistrationWrap(attackerSk, watcherPk, regContent({ action: 'unregister', token: `${FCM_TOKEN}z` }, nowSec + 100)),
      watcherSk,
    );
    s.apply(parseRegistration(rumor, { apps, limits: DEFAULT_LIMITS, allowInsecureRelays: false, nowSec }), nowSec);
    expect(s.apply(parse(regContent({}, nowSec)), nowSec)).toBe('registered');
  });

  it('fails closed (global watermark, full timestamp) when the watermark table is full', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), { ...DEFAULT_LIMITS, maxWatermarkUsers: 1 });
    const other = (sk: Uint8Array, c: Record<string, unknown>) => {
      const { rumor } = unwrapRegistration(makeRegistrationWrap(sk, watcherPk, c), watcherSk);
      return parseRegistration(rumor, { apps, limits: DEFAULT_LIMITS, allowInsecureRelays: false, nowSec });
    };
    s.apply(other(generateSecretKey(), regContent({ action: 'unregister' }, nowSec)), nowSec); // fills the table
    const bSk = generateSecretKey();
    s.apply(other(bSk, regContent({ action: 'unregister' }, nowSec + 60)), nowSec); // no room -> global, unclamped
    // B's older register must not slip in, even though B has no row of its own...
    expect(s.apply(other(bSk, regContent({}, nowSec + 30)), nowSec)).toBe('stale');
    // ...and everyone is delayed at most until the watermark passes (<= clock-skew allowance).
    expect(s.apply(parse(regContent({}, nowSec + 61)), nowSec)).toBe('registered');
  });

  it('eviction never lowers ordering: an older incoming device is refused, and evicted devices stay gone', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), { ...DEFAULT_LIMITS, maxDevicesPerUser: 1 });
    const a = parse(regContent({ token: `${FCM_TOKEN}a` }, nowSec));
    expect(s.apply(a, nowSec)).toBe('registered');
    // B is older than A: refusing it keeps A (and A's ordering) intact.
    expect(s.apply(parse(regContent({ token: `${FCM_TOKEN}b` }, nowSec - 10)), nowSec)).toBe('limit');
    // C is newer: A is evicted, and replaying A can never resurrect it.
    expect(s.apply(parse(regContent({ token: `${FCM_TOKEN}c` }, nowSec + 5)), nowSec)).toBe('registered');
    expect(s.isStale(a)).toBe(true);
    expect(s.apply(a, nowSec)).toBe('stale');
  });

  it('capacity-refused registrations are settled, so their replays are stale', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), { ...DEFAULT_LIMITS, maxRegistrations: 0 });
    const r = parse(regContent({}, nowSec - 5));
    expect(s.apply(r, nowSec)).toBe('limit');
    expect(s.isStale(r)).toBe(true);
  });

  const asUser = (sk: Uint8Array, c: Record<string, unknown>) => {
    const { rumor } = unwrapRegistration(makeRegistrationWrap(sk, watcherPk, c), watcherSk);
    return parseRegistration(rumor, { apps, limits: DEFAULT_LIMITS, allowInsecureRelays: false, nowSec });
  };

  it('global saturation never affects users with a live registration (even after a sweep)', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), { ...DEFAULT_LIMITS, maxWatermarkUsers: 1 });
    // The victim just has one live device: its replay state is reserved on admission.
    s.apply(parse(regContent({ token: `${FCM_TOKEN}1` }, nowSec - 50)), nowSec);
    // Attackers fill the inactive budget and push the global cutoff ahead repeatedly.
    for (let i = 0; i < 5; i++) s.apply(asUser(generateSecretKey(), regContent({ action: 'unregister' }, nowSec + 100 + i)), nowSec);
    expect(s.apply(parse(regContent({ token: `${FCM_TOKEN}2` }, nowSec)), nowSec)).toBe('registered');
    // Sweeping (watermark purge) keeps live users' rows.
    s.sweep(nowSec + 8 * 3600);
    for (let i = 0; i < 3; i++) s.apply(asUser(generateSecretKey(), regContent({ action: 'unregister' }, nowSec + 110 + i)), nowSec);
    expect(s.apply(parse(regContent({ token: `${FCM_TOKEN}3` }, nowSec + 1)), nowSec)).toBe('registered');
  });

  it('watermark bookkeeping is O(1) per request (no table scans)', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), { ...DEFAULT_LIMITS, maxWatermarkUsers: 50_000 });
    const db = (s as unknown as { db: { prepare: (q: string) => { run: (...a: unknown[]) => unknown } } }).db;
    const ins = db.prepare('INSERT INTO user_watermarks (user, ts, active) VALUES (?, ?, 0)');
    for (let i = 0; i < 40_000; i++) ins.run(i.toString(16).padStart(64, '0'), nowSec);
    (s as unknown as { reconcileWatermarks: () => void }).reconcileWatermarks();
    const reqs = Array.from({ length: 100 }, () => asUser(generateSecretKey(), regContent({ action: 'unregister' }, nowSec)));
    const t = performance.now();
    for (const r of reqs) s.apply(r, nowSec);
    const ms = performance.now() - t;
    expect(ms).toBeLessThan(250); // per-request COUNT(*) scans took seconds here
  });

  it('watermark rows stay within budget under register/unregister churn', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), { ...DEFAULT_LIMITS, maxWatermarkUsers: 1, maxRegistrations: 2 });
    for (let i = 0; i < 10; i++) {
      const sk = generateSecretKey();
      s.apply(asUser(sk, regContent({}, nowSec - 20)), nowSec);
      s.apply(asUser(sk, regContent({ action: 'unregister' }, nowSec - 10)), nowSec);
      // ...and the churned user's ordering is still preserved (globally if compacted).
      expect(s.apply(asUser(sk, regContent({}, nowSec - 15)), nowSec)).toBe('stale');
    }
    const db = (s as unknown as { db: { prepare: (q: string) => { get: () => { n: number } } } }).db;
    expect(db.prepare('SELECT COUNT(*) AS n FROM user_watermarks').get().n).toBeLessThanOrEqual(1 + 2);
  });

  it('isStale covers refused and replayed unregisters too, so they never charge the rate allowance', () => {
    const s = store();
    const unreg = parse(regContent({ token: `${FCM_TOKEN}q`, action: 'unregister' }, nowSec - 10));
    expect(s.isStale(unreg)).toBe(false);
    s.apply(unreg, nowSec);
    expect(s.isStale(unreg)).toBe(true);
  });

  it('a dead-token removal blocks replay of that registration', () => {
    const s = store();
    const reg = parse(regContent({}, nowSec - 10));
    s.apply(reg, nowSec);
    const [d] = s.devicesFor(userPk);
    expect(s.removeRegistration(d!.user, d!.tokenHash, d!.ts)).toBe(true);
    expect(s.apply(reg, nowSec)).toBe('stale');
  });

  it('records the APNs environment, falling back to the operator mapping when unstated', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), DEFAULT_LIMITS, ['com.lightningpiggy.app.preview']);
    s.apply(parse(regContent({ platform: 'apns', token: APNS_TOKEN, apns_env: 'sandbox' })), nowSec);
    s.apply(parse(regContent({ platform: 'apns', token: 'cd'.repeat(32), app: 'com.lightningpiggy.app.preview' })), nowSec);
    s.apply(parse(regContent({ platform: 'apns', token: 'ef'.repeat(32) })), nowSec);
    const env = Object.fromEntries(s.devicesFor(userPk).map((d) => [d.token.slice(0, 2), d.apnsEnv]));
    expect(env).toEqual({ aa: 'sandbox', cd: 'sandbox', ef: 'production' });
    expect(reason(() => parse(regContent({ apns_env: 'dev' })))).toBe('bad apns_env');
  });

  it('isCurrent tracks the exact live version and category', () => {
    const s = store();
    s.apply(parse(regContent({ categories: { dm: true } }, nowSec - 10)), nowSec);
    const [d] = s.devicesFor(userPk);
    expect(s.isCurrent(d!.user, d!.tokenHash, d!.ts, 'dm')).toBe(true);
    expect(s.isCurrent(d!.user, d!.tokenHash, d!.ts, 'zap')).toBe(false);
    s.apply(parse(regContent({ action: 'unregister' }, nowSec - 5)), nowSec);
    expect(s.isCurrent(d!.user, d!.tokenHash, d!.ts, 'dm')).toBe(false);
  });

  it('bounds persisted notified ids', () => {
    const s = new Store(':memory:', Buffer.alloc(32, 1), { ...DEFAULT_LIMITS, notifiedMaxRows: 2 });
    expect(s.markNotified('a', nowSec)).toBe(true);
    expect(s.markNotified('a', nowSec)).toBe(false);
    s.markNotified('b', nowSec);
    expect(s.markNotified('c', nowSec)).toBe(true); // over cap: allowed, just not persisted
    expect(s.markNotified('c', nowSec)).toBe(true);
  });

  it('isStale detects replays without mutating', () => {
    const s = store();
    const r = parse(regContent({}, nowSec - 10));
    expect(s.isStale(r)).toBe(false);
    s.apply(r, nowSec);
    expect(s.isStale(r)).toBe(true);
  });
});
