// APNs provider API (HTTP/2, token auth). One client serves every app id: the
// topic is the registration's app id, and the environment (production vs
// sandbox) is chosen per app id.

import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import http2 from 'node:http2';
import { errCode, log } from '../log.js';
import type { Device } from '../store.js';
import { ALERT_TITLE, alertBody, pushData, type PushNotification, type PushResult, type PushSender } from './types.js';

export const APNS_PRODUCTION = 'https://api.push.apple.com';
export const APNS_SANDBOX = 'https://api.sandbox.push.apple.com';
/** Apple rejects provider tokens older than 1 h and throttles refreshes more often than every 20 min. */
const JWT_TTL_MS = 50 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 15_000;

export interface ApnsResponse {
  status: number;
  body: string;
}

export type ApnsTransport = (
  origin: string,
  path: string,
  headers: Record<string, string>,
  body: string,
) => Promise<ApnsResponse>;

const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64url');

export class ApnsSender implements PushSender {
  private readonly key: KeyObject;
  private jwt: { token: string; at: number } | null = null;

  constructor(
    private readonly opts: { keyPem: string; keyId: string; teamId: string },
    private readonly transport: ApnsTransport = http2Transport(),
    private readonly now: () => number = Date.now,
  ) {
    this.key = createPrivateKey(opts.keyPem);
  }

  providerToken(force = false): string {
    const t = this.now();
    if (!force && this.jwt && t - this.jwt.at < JWT_TTL_MS) return this.jwt.token;
    const header = b64url(JSON.stringify({ alg: 'ES256', kid: this.opts.keyId }));
    const claims = b64url(JSON.stringify({ iss: this.opts.teamId, iat: Math.floor(t / 1000) }));
    const sig = sign('sha256', Buffer.from(`${header}.${claims}`), { key: this.key, dsaEncoding: 'ieee-p1363' });
    this.jwt = { token: `${header}.${claims}.${b64url(sig)}`, at: t };
    return this.jwt.token;
  }

  buildRequest(device: Device, n: PushNotification): { origin: string; path: string; headers: Record<string, string>; body: string } {
    const origin = device.apnsEnv === 'sandbox' ? APNS_SANDBOX : APNS_PRODUCTION;
    const payload = {
      aps: {
        alert: { title: ALERT_TITLE, body: alertBody(n) },
        sound: 'default',
        'thread-id': `lp-${n.category}`,
      },
      ...pushData(n),
    };
    return {
      origin,
      path: `/3/device/${device.token}`,
      headers: {
        authorization: `bearer ${this.providerToken()}`,
        'apns-topic': device.app,
        'apns-push-type': 'alert',
        'apns-priority': '10',
        'apns-expiration': String(Math.floor(this.now() / 1000) + 86400),
        'apns-collapse-id': `lp-${n.category}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(payload),
    };
  }

  async send(device: Device, n: PushNotification, stillValid: () => boolean = () => true, retried = false): Promise<PushResult> {
    const req = this.buildRequest(device, n);
    if (!stillValid()) return 'cancelled';
    let res: ApnsResponse;
    try {
      res = await this.transport(req.origin, req.path, req.headers, req.body);
    } catch (e) {
      log.warn('apns transport error', { err: errCode(e) });
      return { retry: true };
    }
    if (res.status === 200) return 'ok';
    let reason = '';
    try {
      reason = String((JSON.parse(res.body) as { reason?: unknown }).reason ?? '');
    } catch {
      /* non-JSON body */
    }
    if (res.status === 410 || reason === 'BadDeviceToken' || reason === 'DeviceTokenNotForTopic' || reason === 'Unregistered') {
      return 'invalid-token';
    }
    if (res.status === 403 && reason === 'ExpiredProviderToken' && !retried) {
      this.providerToken(true);
      return this.send(device, n, stillValid, true);
    }
    if (res.status === 429) return { retry: true, quota: true };
    if (res.status >= 500) return { retry: true };
    log.warn('apns rejected push', { status: res.status, reason: reason.slice(0, 40), app: device.app });
    return 'error';
  }
}

/** Real transport: one cached HTTP/2 session per origin, recreated on close/error. */
export function http2Transport(timeoutMs = REQUEST_TIMEOUT_MS): ApnsTransport {
  const sessions = new Map<string, http2.ClientHttp2Session>();
  const session = (origin: string) => {
    const s = sessions.get(origin);
    if (s && !s.closed && !s.destroyed) return s;
    const ns = http2.connect(origin);
    ns.on('error', (e) => log.warn('apns session error', { err: errCode(e) }));
    // Only evict the cache entry if it is still this session (a replacement may exist).
    const evict = () => {
      if (sessions.get(origin) === ns) sessions.delete(origin);
    };
    ns.on('close', evict);
    ns.on('goaway', () => {
      evict();
      ns.close(); // finish in-flight streams, then go away
    });
    ns.setTimeout(10 * 60_000, () => ns.close());
    sessions.set(origin, ns);
    return ns;
  };
  return (origin, path, headers, body) =>
    new Promise<ApnsResponse>((resolve, reject) => {
      let settled = false;
      const done = (fn: () => void) => {
        if (!settled) {
          settled = true;
          fn();
        }
      };
      const req = session(origin).request({ ':method': 'POST', ':path': path, ...headers });
      let status = 0;
      let data = '';
      req.setEncoding('utf8');
      // A timeout or a stream that ends without a response is a transport
      // failure (retryable), never a completed request.
      req.setTimeout(timeoutMs, () => {
        done(() => reject(new Error('apns request timed out')));
        req.close(http2.constants.NGHTTP2_CANCEL);
      });
      req.on('response', (h) => {
        status = Number(h[':status'] ?? 0);
      });
      req.on('data', (c: string) => {
        if (data.length < 4096) data += c;
      });
      req.on('end', () => done(() => (status ? resolve({ status, body: data }) : reject(new Error('apns stream ended without response')))));
      req.on('error', (e) => done(() => reject(e)));
      req.on('close', () => done(() => reject(new Error('apns stream closed without response'))));
      req.end(body);
    });
}
