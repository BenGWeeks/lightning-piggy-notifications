// Privacy hardening: aggregate-only info logs, admission (token validation,
// new-registration budget, provisional eviction), encryption at rest + migration,
// hashed notified ids, watermark grace, admin tooling.

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { npubEncode } from 'nostr-tools/nip19';
import { DEFAULT_LIMITS, loadConfig, type Limits } from '../src/config.js';
import { parsePubkey } from '../src/admin.js';
import { setLogLevel, setLogSink } from '../src/log.js';
import { ApnsSender, type ApnsTransport } from '../src/push/apns.js';
import { FcmSender } from '../src/push/fcm.js';
import type { PushNotification, PushResult, PushSender, TokenCheck } from '../src/push/types.js';
import { parseRegistration, unwrapRegistration, type RegistrationRequest } from '../src/registration.js';
import { Store, type Device } from '../src/store.js';
import { TokenCrypto } from '../src/tokenCrypto.js';
import { Watcher } from '../src/watcher.js';
import { FCM_TOKEN, makeRegistrationWrap, MiniRelay, regContent, testConfig, waitFor } from './helpers.js';

const KEY = Buffer.alloc(32, 1);
const watcherSk = generateSecretKey();
const watcherPk = getPublicKey(watcherSk);
const apps = ['com.lightningpiggy.app', 'com.lightningpiggy.app.preview', 'com.lightningpiggy.app.dev'];
const nowSec = Math.floor(Date.now() / 1000);

function req(sk: Uint8Array, c: Record<string, unknown>, limits: Limits = DEFAULT_LIMITS): RegistrationRequest {
  const { rumor } = unwrapRegistration(makeRegistrationWrap(sk, watcherPk, c), watcherSk);
  return parseRegistration(rumor, { apps, limits, allowInsecureRelays: false, nowSec });
}

const tmp = () => mkdtempSync(join(tmpdir(), 'lpw-'));

describe('logging: no user or device identifiers at info', () => {
  let relay: MiniRelay;
  let watcher: Watcher;
  let lines: string[];
  let sent: Device[];
  const userSk = generateSecretKey();
  const userPk = getPublicKey(userSk);
  const strangerSk = generateSecretKey();

  beforeEach(async () => {
    lines = [];
    sent = [];
    setLogSink((l) => lines.push(l));
    relay = new MiniRelay();
    await relay.start();
    const sender: PushSender = {
      send: async (device: Device, _n: PushNotification): Promise<PushResult> => {
        sent.push(device);
        return 'ok';
      },
      validate: async (): Promise<TokenCheck> => 'ok',
    };
    const cfg = testConfig({ secretKey: watcherSk, relays: [relay.url] });
    cfg.limits.coalesceWindowSec = 1;
    watcher = new Watcher(cfg, { senders: { fcm: sender, apns: sender } });
  });

  afterEach(async () => {
    await watcher.stop();
    await relay.stop();
    setLogLevel('info');
    setLogSink((l) => process.stdout.write(l + '\n'));
  });

  async function registerAndZap() {
    await watcher.start();
    relay.publish(makeRegistrationWrap(userSk, watcher.pubkey, regContent({ relays: [relay.url] })));
    await waitFor(() => watcher.readyStatus().registrations === 1);
    await new Promise((r) => setTimeout(r, 2_300)); // debounced rebuild + REQs
    relay.publish(
      finalizeEvent({ kind: 9735, created_at: Math.floor(Date.now() / 1000), tags: [['p', userPk]], content: '' }, strangerSk),
    );
    await waitFor(() => sent.length === 1);
  }

  it('logs per-event / per-delivery / per-registration lines only at debug; info gets aggregate counts', async () => {
    setLogLevel('info');
    await registerAndZap();
    watcher.activity.flush();
    const recs = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    for (const r of recs) {
      expect(r).not.toHaveProperty('user');
      expect(r).not.toHaveProperty('device');
      expect(r).not.toHaveProperty('wrap');
    }
    const all = lines.join('\n');
    expect(all).not.toContain(userPk.slice(0, 8));
    expect(all).not.toContain(sent[0]!.tokenHash.slice(0, 8));
    expect(recs.map((r) => r.msg)).not.toContain('event matched');
    expect(recs.map((r) => r.msg)).not.toContain('push delivered');
    expect(recs.map((r) => r.msg)).not.toContain('registration');
    const activity = recs.find((r) => r.msg === 'activity')!;
    expect(activity).toMatchObject({ matched: { zap: 1 }, delivered: { zap: 1 }, registrations: { registered: 1 } });
  });

  it('debug lines use per-process pseudonyms, never pubkey or token-hash prefixes', async () => {
    setLogLevel('debug');
    await registerAndZap();
    const recs = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const matched = recs.find((r) => r.msg === 'event matched')!;
    const delivered = recs.find((r) => r.msg === 'push delivered')!;
    expect(matched.user).toBe(delivered.user); // correlatable within the run
    const all = lines.join('\n');
    expect(all).not.toContain(userPk.slice(0, 8));
    expect(all).not.toContain(sent[0]!.tokenHash.slice(0, 8));
  });
});

describe('admission: token validation, registration budget, provisional eviction', () => {
  it('an invalid token is refused, settled (replay stale) and never stored', () => {
    const s = new Store(':memory:', KEY, DEFAULT_LIMITS);
    const r = req(generateSecretKey(), regContent({}, nowSec - 5));
    expect(s.apply(r, nowSec, 'invalid')).toBe('invalid-token');
    expect(s.countActive()).toBe(0);
    expect(s.isStale(r)).toBe(true);
  });

  it('validated vs provisional; a delivery validates a provisional registration', () => {
    const s = new Store(':memory:', KEY, DEFAULT_LIMITS);
    const sk = generateSecretKey();
    s.apply(req(sk, regContent({ token: `${FCM_TOKEN}a` }, nowSec - 5)), nowSec, 'ok');
    s.apply(req(sk, regContent({ token: `${FCM_TOKEN}b` }, nowSec - 4)), nowSec, 'unavailable');
    expect(s.countProvisional()).toBe(1);
    const prov = s.devicesFor(getPublicKey(sk)).find((d) => d.token.endsWith('b'))!;
    s.markValidated(prov.user, prov.tokenHash, prov.ts, nowSec);
    expect(s.countProvisional()).toBe(0);
    // A refresh keeps the validated state.
    s.apply(req(sk, regContent({ token: `${FCM_TOKEN}b` }, nowSec - 3)), nowSec);
    expect(s.countProvisional()).toBe(0);
  });

  it('at capacity a validated newcomer evicts the oldest provisional registration, never a validated one', () => {
    const s = new Store(':memory:', KEY, { ...DEFAULT_LIMITS, maxRegistrations: 2 });
    const realSk = generateSecretKey();
    const fakeSk = generateSecretKey();
    s.apply(req(realSk, regContent({}, nowSec - 10)), nowSec - 10, 'ok');
    const fake = req(fakeSk, regContent({}, nowSec - 9));
    s.apply(fake, nowSec - 9, 'unavailable');
    // A provisional newcomer can't displace anyone.
    expect(s.apply(req(generateSecretKey(), regContent({}, nowSec - 8)), nowSec, 'unavailable')).toBe('limit');
    // A validated one evicts the provisional row (whose replay is then stale).
    const newSk = generateSecretKey();
    expect(s.wouldAdmit(req(newSk, regContent({}, nowSec - 7)), nowSec)).toBe(true);
    expect(s.apply(req(newSk, regContent({}, nowSec - 7)), nowSec, 'ok')).toBe('registered');
    expect(s.countActive()).toBe(2);
    expect(s.devicesFor(getPublicKey(fakeSk))).toEqual([]);
    expect(s.isStale(fake)).toBe(true);
    // Now everything is validated: further newcomers are refused (before any token check).
    const late = req(generateSecretKey(), regContent({}, nowSec - 6));
    expect(s.wouldAdmit(late, nowSec)).toBe(false);
    expect(s.apply(late, nowSec, 'ok')).toBe('limit');
    expect(s.devicesFor(getPublicKey(realSk))).toHaveLength(1);
  });

  it('new registrations are budgeted per hour (fresh keys and new devices alike); refreshes are not', () => {
    const s = new Store(':memory:', KEY, { ...DEFAULT_LIMITS, maxNewRegistrationsPerHour: 3 });
    const existing = generateSecretKey();
    s.apply(req(existing, regContent({ token: `${FCM_TOKEN}1` }, nowSec - 20)), nowSec, 'ok');
    let admitted = 0;
    for (let i = 0; i < 10; i++) {
      if (s.apply(req(generateSecretKey(), regContent({ token: `${FCM_TOKEN}k${i}` }, nowSec - 10)), nowSec, 'ok') === 'registered') admitted++;
    }
    expect(admitted).toBe(2);
    expect(s.apply(req(existing, regContent({ token: `${FCM_TOKEN}2` }, nowSec - 5)), nowSec, 'ok')).toBe('limit');
    expect(s.apply(req(existing, regContent({ token: `${FCM_TOKEN}1` }, nowSec - 4)), nowSec, 'ok')).toBe('updated');
    // The budget refills next hour.
    expect(s.apply(req(generateSecretKey(), regContent({}, nowSec)), nowSec + 3600, 'ok')).toBe('registered');
  });

  it('one device token is held by at most maxUsersPerToken users (least recently refreshed replaced)', () => {
    const s = new Store(':memory:', KEY, { ...DEFAULT_LIMITS, maxUsersPerToken: 2 });
    const keys = [generateSecretKey(), generateSecretKey(), generateSecretKey(), generateSecretKey()];
    for (const [i, sk] of keys.entries()) expect(s.apply(req(sk, regContent({}, nowSec - 10)), nowSec + i, 'ok')).toBe('registered');
    expect(s.countActive()).toBe(2);
    expect(s.devicesFor(getPublicKey(keys[0]!))).toEqual([]);
    expect(s.devicesFor(getPublicKey(keys[3]!))).toHaveLength(1);
    // The replaced registration's replay is stale.
    expect(s.isStale(req(keys[0]!, regContent({}, nowSec - 10)))).toBe(true);
  });

  it('bounds provider token checks per hour; a device that can\'t be checked is refused, not admitted unchecked', () => {
    const s = new Store(':memory:', KEY, { ...DEFAULT_LIMITS, maxNewRegistrationsPerHour: 1 });
    let taken = 0;
    for (let i = 0; i < 10; i++) if (s.takeTokenCheck(nowSec)) taken++;
    expect(taken).toBe(4);
    expect(s.takeTokenCheck(nowSec + 3600)).toBe(true);
    const r = req(generateSecretKey(), regContent({}, nowSec - 5));
    expect(s.apply(r, nowSec, 'unchecked')).toBe('limit');
    expect(s.countActive()).toBe(0);
    expect(s.isStale(r)).toBe(true);
    // Users with a live registration don't draw on the check budget.
    const s2 = new Store(':memory:', KEY, { ...DEFAULT_LIMITS, maxNewRegistrationsPerHour: 1 });
    const live = generateSecretKey();
    s2.apply(req(live, regContent({}, nowSec - 30)), nowSec, 'ok');
    for (let i = 0; i < 4; i++) s2.takeTokenCheck(nowSec);
    expect(s2.takeTokenCheck(nowSec, getPublicKey(live))).toBe(true);
    expect(s2.takeTokenCheck(nowSec, getPublicKey(generateSecretKey()))).toBe(false);
    const unlimited = new Store(':memory:', KEY, { ...DEFAULT_LIMITS, maxNewRegistrationsPerHour: 0 });
    for (let i = 0; i < 1000; i++) expect(unlimited.takeTokenCheck(nowSec)).toBe(true);
  });

  it('a single key holds at most maxDevicesPerUser slots', () => {
    const s = new Store(':memory:', KEY, { ...DEFAULT_LIMITS, maxDevicesPerUser: 3 });
    const sk = generateSecretKey();
    for (let i = 0; i < 10; i++) s.apply(req(sk, regContent({ token: `${FCM_TOKEN}${i}` }, nowSec - 20 + i)), nowSec + i, 'ok');
    expect(s.countActive()).toBe(3);
  });

  describe('watcher end to end', () => {
    let relay: MiniRelay;
    let watcher: Watcher;
    let checks: number;
    let verdict: TokenCheck;

    beforeEach(async () => {
      relay = new MiniRelay();
      await relay.start();
      checks = 0;
      verdict = 'ok';
      const sender: PushSender = {
        send: async () => 'ok',
        validate: async () => {
          checks++;
          return verdict;
        },
      };
      const cfg = testConfig({ secretKey: watcherSk, relays: [relay.url] });
      cfg.limits.maxRegistrations = 1;
      watcher = new Watcher(cfg, { senders: { fcm: sender, apns: sender } });
      await watcher.start();
    });

    afterEach(async () => {
      await watcher.stop();
      await relay.stop();
    });

    it('checks new tokens before admission, not refreshes, and not when it would refuse anyway', async () => {
      verdict = 'invalid';
      const sk = generateSecretKey();
      relay.publish(makeRegistrationWrap(sk, watcher.pubkey, regContent({}, nowSec - 30)));
      await waitFor(() => watcher.stats.registrations === 1);
      expect(checks).toBe(1);
      expect(watcher.readyStatus().registrations).toBe(0);

      verdict = 'ok';
      relay.publish(makeRegistrationWrap(sk, watcher.pubkey, regContent({}, nowSec - 20)));
      await waitFor(() => watcher.readyStatus().registrations === 1);
      expect(checks).toBe(2);
      expect(watcher.readyStatus().registrations_provisional).toBe(0);
      relay.publish(makeRegistrationWrap(sk, watcher.pubkey, regContent({}, nowSec - 10))); // refresh
      await waitFor(() => watcher.stats.registrations === 3);
      expect(checks).toBe(2);
      // Full of validated registrations: a newcomer is refused without a provider request.
      relay.publish(makeRegistrationWrap(generateSecretKey(), watcher.pubkey, regContent({}, nowSec - 10)));
      await waitFor(() => watcher.stats.registrations === 4);
      expect(checks).toBe(2);
      expect(watcher.readyStatus().registrations).toBe(1);
    });
  });
});

describe('provider token checks', () => {
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const apnsPem = ec.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const target = { token: 'a'.repeat(64), app: 'com.lightningpiggy.app', platform: 'apns' as const, apnsEnv: 'production' as const };

  it('APNs: a silent background push; dead tokens are invalid, provider trouble is unavailable', async () => {
    const calls: Parameters<ApnsTransport>[] = [];
    let res = { status: 200, body: '' };
    const sender = new ApnsSender({ keyPem: apnsPem, keyId: 'K', teamId: 'T' }, async (...a) => {
      calls.push(a);
      return res;
    });
    expect(await sender.validate(target)).toBe('ok');
    const [, , headers, body] = calls[0]!;
    expect(headers['apns-push-type']).toBe('background');
    expect(headers['apns-priority']).toBe('5');
    expect(headers['apns-expiration']).toBe('0');
    expect(JSON.parse(body)).toEqual({ aps: { 'content-available': 1 }, source: 'lp-watcher', type: 'validate' });
    res = { status: 400, body: '{"reason":"BadDeviceToken"}' };
    expect(await sender.validate(target)).toBe('invalid');
    res = { status: 410, body: '{"reason":"Unregistered"}' };
    expect(await sender.validate(target)).toBe('invalid');
    res = { status: 503, body: '' };
    expect(await sender.validate(target)).toBe('unavailable');
    res = { status: 403, body: '{"reason":"InvalidProviderToken"}' };
    expect(await sender.validate(target)).toBe('unavailable');
  });

  it('FCM: validate_only, which delivers nothing', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const sa = { clientEmail: 'svc@p.iam.gserviceaccount.com', privateKeyPem: rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), projectId: 'p' };
    const bodies: string[] = [];
    let status = 200;
    let resp = '{}';
    const sender = new FcmSender(sa, async (url, init) => {
      if (url.includes('oauth2')) return { status: 200, text: async () => '{"access_token":"x","expires_in":3600}' };
      bodies.push(init.body);
      return { status, text: async () => resp };
    });
    const t = { ...target, platform: 'fcm' as const, token: 'tok' };
    expect(await sender.validate(t)).toBe('ok');
    const sentBody = JSON.parse(bodies[0]!) as { validate_only: boolean; message: Record<string, unknown> };
    expect(sentBody.validate_only).toBe(true);
    expect(sentBody.message).toEqual({ token: 'tok', data: { source: 'lp-watcher', type: 'validate' } });
    status = 404;
    resp = JSON.stringify({ error: { status: 'NOT_FOUND', details: [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode: 'UNREGISTERED' }] } });
    expect(await sender.validate(t)).toBe('invalid');
    status = 500;
    resp = '';
    expect(await sender.validate(t)).toBe('unavailable');
  });
});

describe('encryption at rest', () => {
  const nwcClient = 'c1'.repeat(32);
  const nwcWallet = 'e2'.repeat(32);
  const relayUrl = 'wss://secret-relay.example';

  function fileBytes(path: string): Buffer {
    return Buffer.concat([path, `${path}-wal`].filter(existsSync).map((p) => readFileSync(p)));
  }

  it('stores no pubkey, relay or NWC key in the clear; decrypts them for planning; looks up by HMAC', () => {
    const dir = tmp();
    const path = join(dir, 'w.db');
    const s = new Store(path, KEY, DEFAULT_LIMITS);
    const sk = generateSecretKey();
    const user = getPublicKey(sk);
    const r = req(sk, regContent({ relays: [relayUrl] }, nowSec - 5));
    r.nwc = [{ client: nwcClient, wallet: nwcWallet }];
    s.apply(r, nowSec, 'ok');
    s.markNotified('ab'.repeat(32), nowSec);
    const db = (s as unknown as { db: Database.Database }).db;
    db.pragma('wal_checkpoint(TRUNCATE)');
    const bytes = fileBytes(path);
    for (const secret of [user, Buffer.from(user, 'hex').toString('latin1'), relayUrl, nwcClient, nwcWallet, FCM_TOKEN, 'ab'.repeat(32)]) {
      expect(bytes.includes(Buffer.from(secret, 'latin1'))).toBe(false);
    }
    expect(s.listActive()).toEqual([
      expect.objectContaining({ user, relays: [relayUrl], nwc: [{ client: nwcClient, wallet: nwcWallet }] }),
    ]);
    expect(s.devicesFor(user)[0]!.token).toBe(FCM_TOKEN);
    expect(s.isCurrent(user, s.devicesFor(user)[0]!.tokenHash, r.ts, 'dm')).toBe(true);
    s.close();
    // The wrong key refuses to start, and changes nothing.
    expect(() => new Store(path, Buffer.alloc(32, 2), DEFAULT_LIMITS)).toThrow(/token key does not match/);
    const again = new Store(path, KEY, DEFAULT_LIMITS);
    expect(again.countActive()).toBe(1);
    again.close();
    rmSync(dir, { recursive: true });
  });

  it('migrates a v1 (plaintext) database in place: rows, tokens and replay state survive; plaintext is gone', () => {
    const dir = tmp();
    const path = join(dir, 'w.db');
    const crypto = new TokenCrypto(KEY);
    const v1 = new Database(path);
    v1.pragma('journal_mode = WAL');
    v1.exec(`
      CREATE TABLE registrations (user TEXT NOT NULL, token_hash TEXT NOT NULL, app TEXT NOT NULL, platform TEXT NOT NULL,
        token_enc BLOB, categories INTEGER NOT NULL DEFAULT 0, relays TEXT NOT NULL DEFAULT '[]', nwc TEXT NOT NULL DEFAULT '[]',
        ts INTEGER NOT NULL, updated_at INTEGER NOT NULL, apns_env TEXT, PRIMARY KEY (user, token_hash));
      CREATE INDEX registrations_updated ON registrations(updated_at);
      CREATE TABLE notified_events (id TEXT PRIMARY KEY, at INTEGER NOT NULL);
      CREATE INDEX notified_events_at ON notified_events(at);
      CREATE TABLE meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
      CREATE TABLE user_watermarks (user TEXT PRIMARY KEY, ts INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0);
      CREATE INDEX user_watermarks_inactive ON user_watermarks(active, ts);
    `);
    const users = [generateSecretKey(), generateSecretKey()].map((sk) => getPublicKey(sk));
    const app = 'com.lightningpiggy.app';
    for (const [i, user] of users.entries()) {
      const token = `${FCM_TOKEN}${i}`;
      const th = crypto.tokenHash('fcm', app, token);
      v1.prepare('INSERT INTO registrations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        user,
        th,
        app,
        'fcm',
        crypto.encrypt(token, `${user}|${th}|${app}|fcm`),
        0b1111,
        JSON.stringify([relayUrl]),
        JSON.stringify([{ client: nwcClient, wallet: nwcWallet }]),
        nowSec - 100,
        nowSec - 100,
        null,
      );
      v1.prepare('INSERT INTO user_watermarks VALUES (?, ?, 1)').run(user, nowSec - 50);
    }
    const gone = getPublicKey(generateSecretKey()); // unregistered recently: its watermark must survive
    v1.prepare('INSERT INTO user_watermarks VALUES (?, ?, 0)').run(gone, nowSec - 10);
    v1.prepare('INSERT INTO notified_events VALUES (?, ?)').run('ab'.repeat(32), nowSec - 60);
    v1.close();

    const s = new Store(path, KEY, DEFAULT_LIMITS);
    expect(s.countActive()).toBe(2);
    for (const [i, user] of users.entries()) {
      expect(s.devicesFor(user).map((d) => d.token)).toEqual([`${FCM_TOKEN}${i}`]);
    }
    expect(s.listActive().map((r) => r.user).sort()).toEqual([...users].sort());
    expect(s.listActive()[0]!.nwc).toEqual([{ client: nwcClient, wallet: nwcWallet }]);
    // Migrated rows are provisional (never validated under v1).
    expect(s.countProvisional()).toBe(2);
    // Replay state carried over (re-keyed by the HMAC index).
    const goneReq = { user: gone, action: 'register', app, platform: 'fcm', token: FCM_TOKEN, ts: nowSec - 20 } as RegistrationRequest;
    expect(s.isStale(goneReq)).toBe(true);
    // Notified ids carried over as keyed hashes.
    expect(s.markNotified('ab'.repeat(32), nowSec)).toBe(false);
    s.close();
    const bytes = fileBytes(path);
    for (const secret of [...users, gone, relayUrl, nwcClient, nwcWallet, 'ab'.repeat(32)]) {
      expect(bytes.includes(Buffer.from(secret))).toBe(false);
    }
    // Opening again is a no-op.
    const again = new Store(path, KEY, DEFAULT_LIMITS);
    expect(again.countActive()).toBe(2);
    again.close();
    rmSync(dir, { recursive: true });
  });
});

describe('retention', () => {
  it('notified ids are stored as keyed hashes in hour buckets and pruned after the retention', () => {
    const s = new Store(':memory:', KEY, DEFAULT_LIMITS);
    const id = 'ab'.repeat(32);
    expect(s.markNotified(id, nowSec)).toBe(true);
    const db = (s as unknown as { db: Database.Database }).db;
    const row = db.prepare('SELECT id, at FROM notified_events').get() as { id: string; at: number };
    expect(row.id).not.toBe(id);
    expect(row.at % 3600).toBe(0);
    expect(s.sweep(nowSec + DEFAULT_LIMITS.notifiedRetentionSec - 3600).notifiedPruned).toBe(0);
    expect(s.sweep(nowSec + DEFAULT_LIMITS.notifiedRetentionSec + 2 * 3600).notifiedPruned).toBe(1);
  });

  it('keeps an unregistered user’s watermark only as long as the registration timestamp window', () => {
    const s = new Store(':memory:', KEY, DEFAULT_LIMITS);
    const sk = generateSecretKey();
    s.apply(req(sk, regContent({}, nowSec - 20)), nowSec);
    s.apply(req(sk, regContent({ action: 'unregister' }, nowSec - 10)), nowSec);
    const db = (s as unknown as { db: Database.Database }).db;
    const count = () => (db.prepare('SELECT COUNT(*) AS n FROM user_watermarks').get() as { n: number }).n;
    s.sweep(nowSec - 10 + DEFAULT_LIMITS.registrationMaxAgeSec - 60);
    expect(count()).toBe(1);
    s.sweep(nowSec - 10 + DEFAULT_LIMITS.registrationMaxAgeSec + 1);
    expect(count()).toBe(0);
  });

  it('registrations expire after 30 days without a refresh by default', () => {
    expect(DEFAULT_LIMITS.registrationTtlDays).toBe(30);
    const s = new Store(':memory:', KEY, DEFAULT_LIMITS);
    s.apply(req(generateSecretKey(), regContent({}, nowSec - 5)), nowSec);
    expect(s.sweep(nowSec + 29 * 86400).expired).toBe(0);
    expect(s.sweep(nowSec + 30 * 86400 + 1).expired).toBe(1);
  });
});

describe('admin tooling', () => {
  it('lists without tokens, purges by user and purges provisional rows', () => {
    const s = new Store(':memory:', KEY, DEFAULT_LIMITS);
    const a = generateSecretKey();
    const b = generateSecretKey();
    s.apply(req(a, regContent({}, nowSec - 5)), nowSec - 100, 'ok');
    s.apply(req(b, regContent({}, nowSec - 5)), nowSec - 100, 'unavailable');
    const rows = s.adminList();
    expect(rows).toHaveLength(2);
    expect(JSON.stringify(rows)).not.toContain(FCM_TOKEN);
    expect(Object.keys(rows[0]!).sort()).toEqual(['app', 'categories', 'nwc', 'platform', 'relays', 'updatedAt', 'user', 'validated']);
    expect(s.adminList(getPublicKey(a))).toHaveLength(1);
    expect(s.purgeProvisional(nowSec)).toBe(1);
    expect(s.purgeUser(getPublicKey(a))).toBe(1);
    expect(s.countActive()).toBe(0);
    expect(parsePubkey(npubEncode(getPublicKey(a)))).toBe(getPublicKey(a));
    expect(() => parsePubkey('nope')).toThrow();
  });

  it('reads its cap and budget settings from the environment', () => {
    const dir = tmp();
    const k = join(dir, 'k');
    const t = join(dir, 't');
    // (key files only need to parse)
    writeFileSync(k, '11'.repeat(32));
    writeFileSync(t, '22'.repeat(32));
    const cfg = loadConfig({
      WATCHER_PRIVATE_KEY_FILE: k,
      WATCHER_TOKEN_KEY_FILE: t,
      WATCHER_MAX_DEVICES_PER_USER: '4',
      WATCHER_NEW_REGISTRATIONS_PER_HOUR: '0',
      WATCHER_MAX_USERS_PER_TOKEN: '3',
      WATCHER_ACTIVITY_LOG_SECONDS: '60',
    });
    expect(cfg.limits.maxDevicesPerUser).toBe(4);
    expect(cfg.limits.maxNewRegistrationsPerHour).toBe(0);
    expect(cfg.limits.maxUsersPerToken).toBe(3);
    expect(cfg.activityLogSec).toBe(60);
    rmSync(dir, { recursive: true });
  });
});

/** A minimal v1 (plaintext) database with one registration per user. */
function writeV1(path: string, key: Buffer, users: string[]): void {
  const crypto = new TokenCrypto(key);
  const v1 = new Database(path);
  v1.pragma('journal_mode = WAL');
  v1.exec(`
    CREATE TABLE registrations (user TEXT NOT NULL, token_hash TEXT NOT NULL, app TEXT NOT NULL, platform TEXT NOT NULL,
      token_enc BLOB, categories INTEGER NOT NULL DEFAULT 0, relays TEXT NOT NULL DEFAULT '[]', nwc TEXT NOT NULL DEFAULT '[]',
      ts INTEGER NOT NULL, updated_at INTEGER NOT NULL, apns_env TEXT, PRIMARY KEY (user, token_hash));
    CREATE TABLE meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
    CREATE TABLE user_watermarks (user TEXT PRIMARY KEY, ts INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0);
  `);
  const app = 'com.lightningpiggy.app';
  for (const [i, user] of users.entries()) {
    const token = `${FCM_TOKEN}${i}`;
    const th = crypto.tokenHash('fcm', app, token);
    v1.prepare('INSERT INTO registrations VALUES (?, ?, ?, ?, ?, 15, ?, ?, ?, ?, NULL)').run(
      user,
      th,
      app,
      'fcm',
      crypto.encrypt(token, `${user}|${th}|${app}|fcm`),
      '[]',
      '[]',
      nowSec - 100,
      nowSec - 100,
    );
  }
  v1.close();
}

describe('review hardening', () => {
  it('a v1 database opened with the wrong key is refused before migrating, and left untouched', () => {
    const dir = tmp();
    const path = join(dir, 'w.db');
    const user = getPublicKey(generateSecretKey());
    writeV1(path, KEY, [user]);
    expect(() => new Store(path, Buffer.alloc(32, 2), DEFAULT_LIMITS)).toThrow(/token key does not match/);
    const raw = new Database(path, { readonly: true });
    expect((raw.prepare('SELECT COUNT(*) AS n FROM registrations WHERE user = ?').get(user) as { n: number }).n).toBe(1);
    raw.close();
    const s = new Store(path, KEY, DEFAULT_LIMITS);
    expect(s.devicesFor(user)).toHaveLength(1);
    s.close();
    rmSync(dir, { recursive: true });
  });

  it('retries the post-migration cleanup at the next start until it completes', () => {
    const dir = tmp();
    const path = join(dir, 'w.db');
    writeV1(path, KEY, [getPublicKey(generateSecretKey())]);
    const s = new Store(path, KEY, DEFAULT_LIMITS);
    const db = (s as unknown as { db: Database.Database }).db;
    const pending = () => db.prepare(`SELECT v FROM meta WHERE k = 'cleanup_pending'`).get();
    expect(pending()).toBeUndefined();
    // Simulate an interrupted cleanup: the flag survives, and the next open finishes it.
    db.prepare(`INSERT INTO meta (k, v) VALUES ('cleanup_pending', 1)`).run();
    s.close();
    const s2 = new Store(path, KEY, DEFAULT_LIMITS);
    expect((s2 as unknown as { db: Database.Database }).db.prepare(`SELECT v FROM meta WHERE k = 'cleanup_pending'`).get()).toBeUndefined();
    expect(s2.countActive()).toBe(1);
    s2.close();
    rmSync(dir, { recursive: true });
  });

  it('throttles recurring provider warnings and keeps per-delivery failures off info', async () => {
    const lines: string[] = [];
    setLogSink((l) => lines.push(l));
    setLogLevel('info');
    try {
      const { warnThrottled } = await import('../src/log.js');
      for (let i = 0; i < 5; i++) warnThrottled('k-test', 'provider says no', { status: 400 });
      expect(lines.filter((l) => l.includes('provider says no'))).toHaveLength(1);
      const { Notifier } = await import('../src/notifier.js');
      const dev: Device = {
        user: 'u'.repeat(64),
        apnsEnv: 'production',
        ts: 1,
        tokenHash: 'h'.repeat(64),
        app: 'com.lightningpiggy.app',
        platform: 'fcm',
        token: 't',
        categories: { dm: true, zap: true, mention: true, payment: true },
      };
      const n = new Notifier({
        store: { devicesFor: () => [dev], removeRegistration: () => false, isCurrent: () => true, markValidated: () => {} },
        senders: { fcm: { send: async () => 'error' } },
        coalesceWindowSec: 30,
        devicePushesPerHour: 60,
        onRegistrationsChanged: () => {},
      });
      n.notify(dev.user, 'dm');
      await waitFor(() => n.stats.failed === 1);
      expect(lines.some((l) => l.includes('push failed'))).toBe(false);
      await n.drain(100);
    } finally {
      setLogSink((l) => process.stdout.write(l + '\n'));
    }
  });

  describe('token checks never block the inbox; shutdown waits for them', () => {
    let relay: MiniRelay;
    let watcher: Watcher;
    let release: () => void;
    let started: number;

    beforeEach(async () => {
      relay = new MiniRelay();
      await relay.start();
      started = 0;
      const gate = new Promise<void>((r) => (release = r));
      const sender: PushSender = {
        send: async () => 'ok',
        validate: async () => {
          started++;
          await gate;
          return 'ok';
        },
      };
      watcher = new Watcher(testConfig({ secretKey: watcherSk, relays: [relay.url] }), { senders: { fcm: sender, apns: sender } });
      await watcher.start();
    });

    afterEach(async () => {
      release();
      await relay.stop();
    });

    it('a refresh and an unregister are applied while another device waits for its check', async () => {
      const a = generateSecretKey();
      const b = generateSecretKey();
      // A is registered before checks are slow... (store directly, provisional)
      const store = watcher['store'] as Store;
      store.apply(req(a, regContent({ token: `${FCM_TOKEN}a` }, nowSec - 30)), nowSec);
      relay.publish(makeRegistrationWrap(b, watcher.pubkey, regContent({ token: `${FCM_TOKEN}b` }, nowSec - 20))); // waits on its check
      await waitFor(() => started === 1);
      relay.publish(makeRegistrationWrap(a, watcher.pubkey, regContent({ token: `${FCM_TOKEN}a`, action: 'unregister' }, nowSec - 10)));
      await waitFor(() => watcher.readyStatus().registrations === 0);
      release();
      await waitFor(() => watcher.readyStatus().registrations === 1);
      await watcher.stop();
    });

    it('stop() waits for checks in flight and discards their results', async () => {
      relay.publish(makeRegistrationWrap(generateSecretKey(), watcher.pubkey, regContent({}, nowSec - 20)));
      await waitFor(() => started === 1);
      const stopped = watcher.stop();
      setTimeout(() => release(), 50);
      await expect(stopped).resolves.toBeUndefined(); // no use of the closed store
    });
  });
});

describe('routing applies the payment toggle (relay filters do not)', () => {
  it('NWC events only match users with payment pushes on', async () => {
    const { RouteIndex } = await import('../src/router.js');
    const client = 'c'.repeat(64);
    const wallet = 'e'.repeat(64);
    const user = 'a'.repeat(64);
    const base = { tokenHash: 't', app: 'com.lightningpiggy.app', platform: 'fcm' as const, relays: [], nwc: [{ client, wallet }] };
    const ev = { id: 'x', pubkey: wallet, created_at: 1, kind: 23196, tags: [['p', client]], content: '', sig: '' };
    const off = new RouteIndex([{ ...base, user, categories: { dm: true, zap: false, mention: false, payment: false } }]);
    expect(off.route(ev)).toEqual([]);
    const on = new RouteIndex([{ ...base, user, categories: { dm: false, zap: false, mention: false, payment: true } }]);
    expect(on.route(ev)).toEqual([{ user, category: 'payment' }]);
  });
});

describe('shutdown never touches a closed store', () => {
  it('a send finishing after drain() returns is ignored, and queued jobs are dropped', async () => {
    let release!: (r: PushResult) => void;
    const writes: string[] = [];
    const dev: Device = {
      user: 'u'.repeat(64),
      apnsEnv: 'production',
      ts: 1,
      tokenHash: 'h'.repeat(64),
      app: 'com.lightningpiggy.app',
      platform: 'fcm',
      token: 't',
      categories: { dm: true, zap: true, mention: true, payment: true },
    };
    const { Notifier } = await import('../src/notifier.js');
    const n = new Notifier({
      store: {
        devicesFor: () => [dev, { ...dev, tokenHash: 'g'.repeat(64) }],
        removeRegistration: () => {
          writes.push('remove');
          return true;
        },
        isCurrent: () => true,
        markValidated: () => {
          writes.push('validated');
        },
      },
      senders: { fcm: { send: () => new Promise<PushResult>((r) => (release = r)) } },
      coalesceWindowSec: 30,
      devicePushesPerHour: 60,
      concurrency: 1,
      onRegistrationsChanged: () => {},
    });
    n.notify(dev.user, 'dm');
    await waitFor(() => n.stats.attempted === 1);
    await n.drain(50); // times out with the send still in flight
    release('ok');
    await new Promise((r) => setTimeout(r, 20));
    expect(writes).toEqual([]);
    expect(n.stats.attempted).toBe(1); // the queued second job never started
  });
});
