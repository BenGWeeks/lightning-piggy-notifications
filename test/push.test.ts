import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import http2 from 'node:http2';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Notifier } from '../src/notifier.js';
import { ApnsSender, APNS_PRODUCTION, APNS_SANDBOX, http2Transport, type ApnsTransport } from '../src/push/apns.js';
import { FcmSender, isInvalidToken, parseFcmError, retryAfterMs } from '../src/push/fcm.js';
import type { PushResult, PushSender } from '../src/push/types.js';
import type { Device } from '../src/store.js';

const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const apnsPem = ec.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaPem = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

const device = (over: Partial<Device> = {}): Device => ({
  user: 'u'.repeat(64),
  apnsEnv: 'production',
  ts: 100,
  tokenHash: 'h1',
  app: 'com.lightningpiggy.app',
  platform: 'apns',
  token: 'a'.repeat(64),
  categories: { dm: true, zap: true, mention: true, payment: true },
  ...over,
});

describe('ApnsSender', () => {
  it('builds a generic alert request with a valid ES256 provider token', async () => {
    const calls: Parameters<ApnsTransport>[] = [];
    const sender = new ApnsSender(
      { keyPem: apnsPem, keyId: 'KEYID12345', teamId: 'TEAM123456' },
      async (...args) => {
        calls.push(args);
        return { status: 200, body: '' };
      },
    );
    expect(await sender.send(device(), { category: 'zap', count: 1, eventKind: 9735 })).toBe('ok');
    const [origin, path, headers, body] = calls[0]!;
    expect(origin).toBe(APNS_PRODUCTION);
    expect(path).toBe(`/3/device/${'a'.repeat(64)}`);
    expect(headers['apns-topic']).toBe('com.lightningpiggy.app');
    expect(headers['apns-push-type']).toBe('alert');
    const payload = JSON.parse(body) as { aps: { alert: { title: string; body: string } }; category: string };
    expect(payload.aps.alert).toEqual({ title: 'Lightning Piggy', body: 'Zap received' });
    expect(payload.category).toBe('zap');
    expect(body).not.toContain('a'.repeat(64));

    const jwt = headers.authorization!.replace('bearer ', '');
    const [h, c, s] = jwt.split('.');
    expect(JSON.parse(Buffer.from(h!, 'base64url').toString())).toEqual({ alg: 'ES256', kid: 'KEYID12345' });
    expect(JSON.parse(Buffer.from(c!, 'base64url').toString()).iss).toBe('TEAM123456');
    const ok = verify('sha256', Buffer.from(`${h}.${c}`), { key: createPublicKey(apnsPem), dsaEncoding: 'ieee-p1363' }, Buffer.from(s!, 'base64url'));
    expect(ok).toBe(true);

    await sender.send(device({ app: 'com.lightningpiggy.app.dev', apnsEnv: 'sandbox' }), { category: 'dm', count: 3, eventKind: 1059 });
    expect(calls[1]![0]).toBe(APNS_SANDBOX);
    expect(JSON.parse(calls[1]![3]).aps.alert.body).toBe('3 new messages');
  });

  it('maps dead-token responses to invalid-token', async () => {
    for (const [status, reason, want] of [
      [410, 'Unregistered', 'invalid-token'],
      [400, 'BadDeviceToken', 'invalid-token'],
      [400, 'DeviceTokenNotForTopic', 'invalid-token'],
      [400, 'BadTopic', 'error'],
    ] as const) {
      const sender = new ApnsSender(
        { keyPem: apnsPem, keyId: 'K', teamId: 'T' },
        async () => ({ status, body: JSON.stringify({ reason }) }),
      );
      expect(await sender.send(device(), { category: 'dm', count: 1, eventKind: 4 })).toBe(want);
    }
  });

  it('marks throttling and server errors retryable', async () => {
    for (const [status, want] of [
      [429, { retry: true, quota: true }],
      [500, { retry: true }],
      [503, { retry: true }],
    ] as const) {
      const sender = new ApnsSender({ keyPem: apnsPem, keyId: 'K', teamId: 'T' }, async () => ({ status, body: '{}' }));
      expect(await sender.send(device(), { category: 'dm', count: 1, eventKind: 4 })).toEqual(want);
    }
  });

  it('re-checks registration validity before every request, including the token-refresh retry', async () => {
    let n = 0;
    let valid = true;
    const sender = new ApnsSender({ keyPem: apnsPem, keyId: 'K', teamId: 'T' }, async () => {
      n++;
      valid = false; // unregistered while the first request was in flight
      return { status: 403, body: '{"reason":"ExpiredProviderToken"}' };
    });
    expect(await sender.send(device(), { category: 'dm', count: 1, eventKind: 4 }, () => valid)).toBe('cancelled');
    expect(n).toBe(1);
  });

  it('http2 transport: a server that never answers is a retryable timeout, not a permanent error', async () => {
    const server = http2.createServer();
    server.on('stream', () => {
      /* accept, never respond */
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as { port: number }).port;
    const transport = http2Transport(200);
    const sender = new ApnsSender({ keyPem: apnsPem, keyId: 'K', teamId: 'T' }, (_o, path, headers, body) =>
      transport(`http://127.0.0.1:${port}`, path, headers, body),
    );
    expect(await sender.send(device(), { category: 'dm', count: 1, eventKind: 4 })).toEqual({ retry: true });
    server.close();
  });

  it('http2 transport: returns real responses', async () => {
    const server = http2.createServer();
    server.on('stream', (stream) => {
      stream.respond({ ':status': 410 });
      stream.end('{"reason":"Unregistered"}');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as { port: number }).port;
    const transport = http2Transport(2_000);
    const res = await transport(`http://127.0.0.1:${port}`, '/3/device/x', {}, '{}');
    expect(res).toEqual({ status: 410, body: '{"reason":"Unregistered"}' });
    server.close();
  });

  it('refreshes an expired provider token once', async () => {
    let n = 0;
    const sender = new ApnsSender({ keyPem: apnsPem, keyId: 'K', teamId: 'T' }, async () =>
      ++n === 1 ? { status: 403, body: '{"reason":"ExpiredProviderToken"}' } : { status: 200, body: '' },
    );
    expect(await sender.send(device(), { category: 'dm', count: 1, eventKind: 4 })).toBe('ok');
    expect(n).toBe(2);
  });
});

describe('FcmSender', () => {
  const sa = { clientEmail: 'svc@proj.iam.gserviceaccount.com', privateKeyPem: rsaPem, projectId: 'proj-1' };

  it('gets an OAuth token and sends a notification + data message', async () => {
    const calls: { url: string; body: string; headers: Record<string, string> }[] = [];
    const sender = new FcmSender(sa, async (url, init) => {
      calls.push({ url, body: init.body, headers: init.headers });
      if (url.includes('oauth2')) return { status: 200, text: async () => '{"access_token":"ya29.x","expires_in":3600}' };
      return { status: 200, text: async () => '{"name":"projects/proj-1/messages/1"}' };
    });
    const d = device({ platform: 'fcm', token: 'tok-123' });
    expect(await sender.send(d, { category: 'payment', count: 1, eventKind: 23197 })).toBe('ok');
    expect(await sender.send(d, { category: 'mention', count: 2, eventKind: 1 })).toBe('ok');
    expect(calls.filter((c) => c.url.includes('oauth2'))).toHaveLength(1); // cached
    const assertion = new URLSearchParams(calls[0]!.body).get('assertion')!;
    const [h, c, s] = assertion.split('.');
    expect(JSON.parse(Buffer.from(c!, 'base64url').toString())).toMatchObject({ iss: sa.clientEmail, aud: 'https://oauth2.googleapis.com/token' });
    expect(verify('sha256', Buffer.from(`${h}.${c}`), rsa.publicKey, Buffer.from(s!, 'base64url'))).toBe(true);
    expect(calls[1]!.url).toBe('https://fcm.googleapis.com/v1/projects/proj-1/messages:send');
    expect(calls[1]!.headers.authorization).toBe('Bearer ya29.x');
    const msg = JSON.parse(calls[1]!.body).message;
    expect(msg.token).toBe('tok-123');
    expect(msg.notification).toEqual({ title: 'Lightning Piggy', body: 'Payment received' });
    expect(msg.data).toEqual({ source: 'lp-watcher', category: 'payment', kind: '23197' });
    expect(msg.android.notification).toEqual({ tag: 'lp-payment', channel_id: 'payments' });
    expect(JSON.parse(calls[2]!.body).message.notification.body).toBe('2 new mentions');
  });

  it('classifies invalid-token errors', async () => {
    const unregistered = JSON.stringify({
      error: { status: 'NOT_FOUND', message: 'Requested entity was not found.', details: [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode: 'UNREGISTERED' }] },
    });
    const malformed = JSON.stringify({ error: { status: 'INVALID_ARGUMENT', message: 'The registration token is not a valid FCM registration token' } });
    const badPayload = JSON.stringify({ error: { status: 'INVALID_ARGUMENT', message: 'Invalid JSON payload received.' } });
    const genericNotFound = JSON.stringify({ error: { status: 'NOT_FOUND', message: 'Requested entity was not found.' } });
    const p = (b: string) => parseFcmError(b);
    expect(isInvalidToken(404, p(genericNotFound).code, p(genericNotFound).message)).toBe(false);
    expect(isInvalidToken(404, p(unregistered).code, p(unregistered).message)).toBe(true);
    expect(isInvalidToken(400, p(malformed).code, p(malformed).message)).toBe(true);
    expect(isInvalidToken(400, p(badPayload).code, p(badPayload).message)).toBe(false);

    const sender = new FcmSender(sa, async (url) =>
      url.includes('oauth2') ? { status: 200, text: async () => '{"access_token":"t"}' } : { status: 400, text: async () => malformed },
    );
    expect(await sender.send(device({ platform: 'fcm' }), { category: 'dm', count: 1, eventKind: 4 })).toBe('invalid-token');
  });

  it('waits at least a minute on quota errors without Retry-After, and consumes success bodies', async () => {
    let read = 0;
    const sender = new FcmSender(sa, async (url) =>
      url.includes('oauth2')
        ? { status: 200, text: async () => '{"access_token":"t"}' }
        : { status: 429, text: async () => (read++, '{}') },
    );
    expect(await sender.send(device({ platform: 'fcm' }), { category: 'dm', count: 1, eventKind: 4 })).toEqual({ retry: true, quota: true });
    const ok = new FcmSender(sa, async (url) =>
      url.includes('oauth2') ? { status: 200, text: async () => '{"access_token":"t"}' } : { status: 200, text: async () => (read++, '{}') },
    );
    await ok.send(device({ platform: 'fcm' }), { category: 'dm', count: 1, eventKind: 4 });
    expect(read).toBe(2);
  });

  it('does not send if the registration changed while waiting for OAuth', async () => {
    let valid = true;
    let pushes = 0;
    const sender = new FcmSender(sa, async (url) => {
      if (url.includes('oauth2')) {
        valid = false; // unregister lands during the OAuth round trip
        return { status: 200, text: async () => '{"access_token":"t"}' };
      }
      pushes++;
      return { status: 200, text: async () => '{}' };
    });
    expect(await sender.send(device({ platform: 'fcm' }), { category: 'dm', count: 1, eventKind: 4 }, () => valid)).toBe('cancelled');
    expect(pushes).toBe(0);
  });

  it('retries throttling with Retry-After', async () => {
    const sender = new FcmSender(sa, async (url) =>
      url.includes('oauth2')
        ? { status: 200, text: async () => '{"access_token":"t"}' }
        : { status: 429, text: async () => '{"error":{"status":"RESOURCE_EXHAUSTED"}}', headers: { get: () => '7' } },
    );
    expect(await sender.send(device({ platform: 'fcm' }), { category: 'dm', count: 1, eventKind: 4 })).toEqual({ retry: true, quota: true, afterMs: 7000 });
    expect(retryAfterMs('9999')).toBe(9_999_000); // not shortened; the notifier drops what it can't honour
    expect(retryAfterMs(null)).toBeUndefined();
  });
});

describe('Notifier', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  function setup(result: PushResult | (() => PushResult) = 'ok', devicesPerHour = 60) {
    const sent: { count: number; category: string }[] = [];
    const removed: string[] = [];
    let changed = 0;
    let devices = [device({ platform: 'fcm' })];
    let current = true;
    const sender: PushSender = {
      send: async (_d, n) => {
        sent.push({ count: n.count, category: n.category });
        return typeof result === 'function' ? result() : result;
      },
    };
    const notifier = new Notifier({
      store: {
        devicesFor: () => devices,
        removeRegistration: (_u: string, h: string, ts: number) => {
          removed.push(`${h}@${ts}`);
          devices = [];
          return true;
        },
        isCurrent: () => current,
      },
      senders: { fcm: sender },
      coalesceWindowSec: 30,
      devicePushesPerHour: devicesPerHour,
      onRegistrationsChanged: () => changed++,
    });
    return { notifier, sent, removed, changed: () => changed, setCurrent: (v: boolean) => (current = v) };
  }

  it('coalesces bursts per (user, category): one immediate push, one summary per window', async () => {
    const { notifier, sent } = setup();
    for (let i = 0; i < 5; i++) notifier.notify('u', 'dm', 1059);
    notifier.notify('u', 'zap', 9735);
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toEqual([
      { count: 1, category: 'dm' },
      { count: 1, category: 'zap' },
    ]);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(sent).toContainEqual({ count: 4, category: 'dm' });
    expect(sent).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(sent).toHaveLength(3); // quiet: nothing more
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(4);
  });

  it('skips devices with the category off', async () => {
    const { notifier, sent } = setup();
    notifier['deps'].store.devicesFor = () => [device({ platform: 'fcm', categories: { dm: false, zap: true, mention: true, payment: true } })];
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(0);
  });

  it('rate-limits per device', async () => {
    const { notifier, sent } = setup('ok', 2);
    for (const c of ['dm', 'zap', 'mention', 'payment'] as const) notifier.notify('u', c, 1);
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(2);
    expect(notifier.stats.rateLimited).toBe(2);
  });

  it('does not send to registrations that changed after the job was queued', async () => {
    const { notifier, sent, setCurrent } = setup();
    setCurrent(false);
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(0);
    expect(notifier.stats.dropped).toBe(1);
  });

  it('backs off quota errors from 60 s and never retries before Retry-After', async () => {
    const { notifier, sent } = setup(() => ({ retry: true, quota: true, afterMs: 7_000 }));
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(59_000);
    expect(sent).toHaveLength(1); // 7 s Retry-After does not shorten the 60 s quota floor
    await vi.advanceTimersByTimeAsync(62_000);
    expect(sent).toHaveLength(2);
  });

  it('drops retries whose required delay outlives the job', async () => {
    const { notifier, sent } = setup(() => ({ retry: true, afterMs: 3_600_000 }));
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toHaveLength(1);
    expect(notifier.stats.retried).toBe(0);
    expect(notifier.stats.failed).toBe(1);
  });

  it('counts deferred retries against the work budget', async () => {
    const many = Array.from({ length: 30 }, (_, i) => device({ platform: 'fcm', tokenHash: `h${i}` }));
    const notifier = new Notifier({
      store: { devicesFor: () => many, removeRegistration: () => false, isCurrent: () => true },
      senders: { fcm: { send: async () => ({ retry: true }) } },
      coalesceWindowSec: 30,
      devicePushesPerHour: 60,
      concurrency: 1,
      queueMax: 5,
      onRegistrationsChanged: () => {},
    });
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(0);
    expect(notifier['retryTimers'].size + notifier['queue'].length).toBeLessThanOrEqual(5);
    expect(notifier.stats.dropped).toBeGreaterThan(0);
  });

  it('retries transient failures a bounded number of times', async () => {
    const { notifier, sent } = setup(() => ({ retry: true }));
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(sent).toHaveLength(3); // first try + 2 retries
    expect(notifier.stats.retried).toBe(2);
    expect(notifier.stats.failed).toBe(1);
  });

  it('bounds concurrent sends', async () => {
    let inflight = 0;
    let peak = 0;
    const many = Array.from({ length: 20 }, (_, i) => device({ platform: 'fcm', tokenHash: `h${i}` }));
    const notifier = new Notifier({
      store: { devicesFor: () => many, removeRegistration: () => false, isCurrent: () => true },
      senders: {
        fcm: {
          send: async () => {
            peak = Math.max(peak, ++inflight);
            await new Promise((r) => setTimeout(r, 10));
            inflight--;
            return 'ok';
          },
        },
      },
      coalesceWindowSec: 30,
      devicePushesPerHour: 60,
      concurrency: 4,
      onRegistrationsChanged: () => {},
    });
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(notifier.stats.delivered).toBe(20);
    expect(peak).toBe(4);
  });

  it('removes registrations whose token is invalid', async () => {
    const { notifier, removed, changed } = setup('invalid-token');
    notifier.notify('u', 'dm', 4);
    await vi.advanceTimersByTimeAsync(0);
    expect(removed).toEqual(['h1@100']); // exactly the version that was sent
    expect(changed()).toBe(1);
    expect(notifier.stats.invalidTokens).toBe(1);
  });
});
