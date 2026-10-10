import type { Category } from '../registration.js';
import type { Device } from '../store.js';

export interface PushNotification {
  category: Category;
  /** Events folded into this push (>= 1). */
  count: number;
}

/** What a token check needs (no registration state). */
export type TokenTarget = Pick<Device, 'token' | 'app' | 'platform' | 'apnsEnv'>;

/**
 * Admission check of a device token, without showing anything to the user:
 * `ok` the provider accepted it; `invalid` the provider says it is dead or not
 * for this app; `unavailable` the check couldn't be made (provider down,
 * throttled, misconfigured) — the registration is then admitted provisionally.
 */
export type TokenCheck = 'ok' | 'invalid' | 'unavailable';

/** Transient failure (throttling, 5xx, network): try again later. */
export interface RetryLater {
  retry: true;
  /** Provider-requested delay (e.g. FCM Retry-After), if any — a minimum, never shortened. */
  afterMs?: number;
  /** Quota/throttling: back off from 60 s instead of 2 s. */
  quota?: boolean;
}

/**
 * `invalid-token`: the device token is dead for this registration — delete it.
 * `error`: permanent failure for this push (not retried).
 */
export type PushResult = 'ok' | 'invalid-token' | 'error' | 'cancelled' | RetryLater;

export const isRetry = (r: PushResult): r is RetryLater => typeof r === 'object' && r.retry;

export interface PushSender {
  /**
   * `stillValid` is checked after credentials are obtained and immediately
   * before every provider request (incl. internal retries); if it returns
   * false the send is abandoned with 'cancelled'.
   */
  send(device: Device, n: PushNotification, stillValid?: () => boolean): Promise<PushResult>;
  /** Validate a token with no visible notification (FCM `validate_only`, APNs background push). */
  validate?(target: TokenTarget): Promise<TokenCheck>;
}

export const ALERT_TITLE = 'Lightning Piggy';

const SINGLE: Record<Category, string> = {
  dm: 'New message',
  zap: 'Zap received',
  mention: 'New mention',
  payment: 'Payment received',
};
const PLURAL: Record<Category, (n: number) => string> = {
  dm: (n) => `${n} new messages`,
  zap: (n) => `${n} zaps received`,
  mention: (n) => `${n} new mentions`,
  payment: (n) => `${n} payments received`,
};

/** Generic text only — the app fills in details after it opens. */
export function alertBody(n: PushNotification): string {
  return n.count > 1 ? PLURAL[n.category](n.count) : SINGLE[n.category];
}

/**
 * Data payload for tap routing: dm -> Messages, zap/payment -> Home, mention -> Notifications.
 * The category is all the app needs; nothing finer (e.g. the Nostr kind) is sent.
 */
export function pushData(n: PushNotification): Record<string, string> {
  return { source: 'lp-watcher', category: n.category };
}

/** Data of the silent admission check (APNs background push; FCM never delivers it). */
export const VALIDATION_DATA = { source: 'lp-watcher', type: 'validate' } as const;
