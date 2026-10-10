// FCM HTTP v1 with OAuth2 service-account auth (JWT bearer grant).

import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { errCode, warnThrottled } from '../log.js';
import type { Device } from '../store.js';
import {
  ALERT_TITLE,
  alertBody,
  pushData,
  VALIDATION_DATA,
  type PushNotification,
  type PushResult,
  type PushSender,
  type TokenCheck,
  type TokenTarget,
} from './types.js';

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
const REQUEST_TIMEOUT_MS = 15_000;

interface FetchResponse {
  status: number;
  text(): Promise<string>;
  headers?: { get(name: string): string | null };
}
type FetchFn = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal },
) => Promise<FetchResponse>;

/** Retry-After (seconds or HTTP date) -> ms. Not capped: the notifier drops jobs it can't honour. */
export function retryAfterMs(h: string | null | undefined, now = Date.now()): number | undefined {
  if (!h) return undefined;
  const secs = Number(h);
  const ms = Number.isFinite(secs) ? secs * 1000 : Date.parse(h) - now;
  return Number.isFinite(ms) && ms > 0 ? ms : undefined;
}


const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64url');

export class FcmSender implements PushSender {
  private readonly key: KeyObject;
  private access: { token: string; exp: number } | null = null;

  constructor(
    private readonly opts: { clientEmail: string; privateKeyPem: string; projectId: string },
    private readonly fetchFn: FetchFn = (url, init) => fetch(url, init),
    private readonly now: () => number = Date.now,
  ) {
    this.key = createPrivateKey(opts.privateKeyPem);
  }

  private assertion(): string {
    const iat = Math.floor(this.now() / 1000);
    const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const claims = b64url(JSON.stringify({ iss: this.opts.clientEmail, scope: SCOPE, aud: TOKEN_URL, iat, exp: iat + 3600 }));
    const sig = sign('sha256', Buffer.from(`${header}.${claims}`), this.key);
    return `${header}.${claims}.${b64url(sig)}`;
  }

  async accessToken(force = false): Promise<string> {
    const t = this.now();
    if (!force && this.access && t < this.access.exp - 5 * 60_000) return this.access.token;
    const res = await this.fetchFn(TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: this.assertion(),
      }).toString(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await res.text();
    if (res.status !== 200) throw new Error(`fcm oauth failed: HTTP ${res.status}`);
    const j = JSON.parse(text) as { access_token?: string; expires_in?: number };
    if (!j.access_token) throw new Error('fcm oauth: no access_token');
    this.access = { token: j.access_token, exp: t + (j.expires_in ?? 3600) * 1000 };
    return this.access.token;
  }

  buildMessage(device: TokenTarget, n: PushNotification): Record<string, unknown> {
    return {
      message: {
        token: device.token,
        notification: { title: ALERT_TITLE, body: alertBody(n) },
        data: pushData(n),
        android: {
          priority: 'high',
          collapse_key: `lp-${n.category}`,
          ttl: '86400s',
          notification: { tag: `lp-${n.category}`, channel_id: androidChannel(n.category) },
        },
      },
    };
  }

  async send(device: Device, n: PushNotification, stillValid: () => boolean = () => true, retried = false): Promise<PushResult> {
    let res: FetchResponse;
    try {
      const token = await this.accessToken();
      // The registration may have changed while we waited for OAuth.
      if (!stillValid()) return 'cancelled';
      res = await this.fetchFn(`https://fcm.googleapis.com/v1/projects/${this.opts.projectId}/messages:send`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify(this.buildMessage(device, n)),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (e) {
      warnThrottled(`fcm transport ${errCode(e)}`, 'fcm transport error', { err: errCode(e) });
      return { retry: true };
    }
    // Always consume the body so the connection is released promptly.
    const body = await res.text().catch(() => '');
    if (res.status === 200) return 'ok';
    const { code, message } = parseFcmError(body);
    if (res.status === 401 && !retried) {
      this.access = null;
      return this.send(device, n, stillValid, true);
    }
    if (isInvalidToken(res.status, code, message)) return 'invalid-token';
    const after = retryAfterMs(res.headers?.get('retry-after'));
    // Quota: the notifier backs off from 60 s (FCM guidance) and never earlier than Retry-After.
    if (res.status === 429 || code === 'QUOTA_EXCEEDED') return { retry: true, quota: true, afterMs: after };
    if (res.status >= 500 || code === 'UNAVAILABLE' || code === 'INTERNAL') return { retry: true, afterMs: after };
    warnThrottled(`fcm push ${res.status} ${code.slice(0, 40)} ${device.app}`, 'fcm rejected push', { status: res.status, code: code.slice(0, 40), app: device.app });
    return 'error';
  }

  /**
   * Admission check: `validate_only` makes FCM check the message (including
   * the token) without delivering anything to the device.
   */
  async validate(t: TokenTarget, retried = false): Promise<TokenCheck> {
    let res: FetchResponse;
    try {
      const token = await this.accessToken();
      res = await this.fetchFn(`https://fcm.googleapis.com/v1/projects/${this.opts.projectId}/messages:send`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ validate_only: true, message: { token: t.token, data: { ...VALIDATION_DATA } } }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (e) {
      warnThrottled(`fcm transport ${errCode(e)}`, 'fcm transport error', { err: errCode(e) });
      return 'unavailable';
    }
    const body = await res.text().catch(() => '');
    if (res.status === 200) return 'ok';
    const { code, message } = parseFcmError(body);
    if (res.status === 401 && !retried) {
      this.access = null;
      return this.validate(t, true);
    }
    if (isInvalidToken(res.status, code, message)) return 'invalid';
    if (res.status !== 429 && res.status < 500) {
      warnThrottled(`fcm check ${res.status} ${code.slice(0, 40)} ${t.app}`, 'fcm rejected token check', { status: res.status, code: code.slice(0, 40), app: t.app });
    }
    return 'unavailable';
  }
}

/** The Lightning Piggy app's Android channels; Android falls back to the default channel if absent. */
export function androidChannel(category: PushNotification['category']): string {
  return category === 'zap' || category === 'payment' ? 'payments' : 'messages';
}

export function parseFcmError(body: string): { code: string; message: string } {
  try {
    const j = JSON.parse(body) as {
      error?: { status?: string; message?: string; details?: { '@type'?: string; errorCode?: string }[] };
    };
    const detail = j.error?.details?.find((d) => d['@type']?.includes('FcmError'))?.errorCode;
    return { code: detail ?? j.error?.status ?? '', message: j.error?.message ?? '' };
  } catch {
    return { code: '', message: '' };
  }
}

export function isInvalidToken(status: number, code: string, message: string): boolean {
  // Only token-specific FcmError codes: a generic NOT_FOUND could be a wrong
  // project id or API path and must not wipe registrations.
  if (code === 'UNREGISTERED' || code === 'SENDER_ID_MISMATCH') return true;
  // A malformed token is INVALID_ARGUMENT; so is a malformed payload — only the
  // former mentions the registration token.
  return status === 400 && code === 'INVALID_ARGUMENT' && /registration token/i.test(message);
}
