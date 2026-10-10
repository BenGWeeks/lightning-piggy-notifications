import type { Category } from '../registration.js';
import type { Device } from '../store.js';

export interface PushNotification {
  category: Category;
  /** Events folded into this push (>= 1). */
  count: number;
  /** Nostr kind of the (last) triggering event — routing hint only. */
  eventKind: number;
}

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

/** Data payload for tap routing: dm -> Messages, zap/payment -> Home, mention -> Notifications. */
export function pushData(n: PushNotification): Record<string, string> {
  return { source: 'lp-watcher', category: n.category, kind: String(n.eventKind) };
}
