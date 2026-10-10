// Coalescing + delivery.
//
// * Per (user, category): the first event pushes immediately and opens a
//   window; events inside the window are counted and sent as one "N new …"
//   push when it closes (which opens the next window), so a burst yields at
//   most one push per window.
// * Per device: a token bucket (bursts up to N, refilling at N per hour).
// * Globally: sends go through one bounded queue with fixed concurrency, so a
//   single event fanning out to many users can't open unbounded requests.
// * Transient provider failures are retried (bounded, with backoff or the
//   provider's Retry-After). Dead tokens remove exactly the registration
//   version that was sent.

import { errCode, log, short } from './log.js';
import type { Category } from './registration.js';
import type { Device, Store } from './store.js';
import { isRetry, type PushNotification, type PushResult, type PushSender } from './push/types.js';

interface Window {
  timer: NodeJS.Timeout;
  pending: number;
  lastKind: number;
}

interface Job {
  device: Device;
  n: PushNotification;
  attempt: number;
  /** Absolute expiry (ms): a push this late is no longer useful. */
  expiresAt: number;
}

const MAX_RETRIES = 2;
/** Jobs (incl. retries) older than this are dropped rather than sent late. */
const JOB_TTL_MS = 10 * 60_000;

export interface NotifierDeps {
  store: Pick<Store, 'devicesFor' | 'removeRegistration' | 'isCurrent'>;
  senders: { apns?: PushSender; fcm?: PushSender };
  coalesceWindowSec: number;
  devicePushesPerHour: number;
  concurrency?: number;
  queueMax?: number;
  /** Called after registrations were removed (invalid tokens) so routing can rebuild. */
  onRegistrationsChanged: () => void;
  now?: () => number;
}

export interface NotifierStats {
  attempted: number;
  delivered: number;
  invalidTokens: number;
  rateLimited: number;
  retried: number;
  failed: number;
  dropped: number;
}

export class Notifier {
  private readonly windows = new Map<string, Window>();
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  readonly stats: NotifierStats = { attempted: 0, delivered: 0, invalidTokens: 0, rateLimited: 0, retried: 0, failed: 0, dropped: 0 };
  private readonly now: () => number;
  private readonly queue: Job[] = [];
  private running = 0;
  private readonly retryTimers = new Set<NodeJS.Timeout>();
  private idleWaiters: (() => void)[] = [];
  private stopped = false;

  constructor(private readonly deps: NotifierDeps) {
    this.now = deps.now ?? Date.now;
  }

  /** An event matched (user, category). */
  notify(user: string, category: Category, eventKind: number): void {
    if (this.stopped) return;
    const key = `${user}|${category}`;
    const w = this.windows.get(key);
    if (w) {
      w.pending++;
      w.lastKind = eventKind;
      return;
    }
    this.openWindow(key, user, category);
    this.fanOut(user, { category, count: 1, eventKind });
  }

  private openWindow(key: string, user: string, category: Category): void {
    const timer = setTimeout(() => {
      const cur = this.windows.get(key);
      this.windows.delete(key);
      if (cur && cur.pending > 0 && !this.stopped) {
        this.openWindow(key, user, category);
        this.fanOut(user, { category, count: cur.pending, eventKind: cur.lastKind });
      }
    }, this.deps.coalesceWindowSec * 1000);
    timer.unref();
    this.windows.set(key, { timer, pending: 0, lastKind: 0 });
  }

  private fanOut(user: string, n: PushNotification): void {
    let devices: Device[];
    try {
      devices = this.deps.store.devicesFor(user).filter((d) => d.categories[n.category]);
    } catch (e) {
      log.error('device lookup failed', { err: e as Error });
      return;
    }
    for (const device of devices) {
      if (!this.takeToken(device.tokenHash)) {
        this.stats.rateLimited++;
        continue;
      }
      this.enqueue({ device, n, attempt: 0, expiresAt: this.now() + JOB_TTL_MS });
    }
  }

  private enqueue(job: Job): void {
    // One admission budget for queued + running + deferred (retry) work.
    if (this.queue.length + this.running + this.retryTimers.size >= (this.deps.queueMax ?? 10_000)) {
      this.stats.dropped++;
      return;
    }
    this.queue.push(job);
    this.pump();
  }

  private pump(): void {
    const max = this.deps.concurrency ?? 32;
    while (this.running < max && this.queue.length > 0) {
      const job = this.queue.shift()!;
      this.running++;
      this.send(job)
        .catch((e: unknown) => log.error('push job failed', { err: e as Error }))
        .finally(() => {
          this.running--;
          this.pump();
          if (this.running === 0 && this.queue.length === 0) {
            for (const w of this.idleWaiters.splice(0)) w();
          }
        });
    }
  }

  private takeToken(tokenHash: string): boolean {
    const cap = this.deps.devicePushesPerHour;
    const t = this.now();
    const b = this.buckets.get(tokenHash) ?? { tokens: cap, at: t };
    b.tokens = Math.min(cap, b.tokens + ((t - b.at) / 3_600_000) * cap);
    b.at = t;
    this.buckets.set(tokenHash, b);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  private async send(job: Job): Promise<void> {
    const { device: d, n } = job;
    const sender = d.platform === 'apns' ? this.deps.senders.apns : this.deps.senders.fcm;
    if (!sender) {
      log.warn('no sender configured for platform', { platform: d.platform });
      return;
    }
    if (this.now() > job.expiresAt) {
      this.stats.dropped++;
      return;
    }
    // The registration may have been unregistered, refreshed or narrowed since
    // this job was queued: only send to the exact live version with the category on.
    let current = false;
    try {
      current = this.deps.store.isCurrent(d.user, d.tokenHash, d.ts, n.category);
    } catch (e) {
      log.error('registration check failed', { err: e as Error });
    }
    if (!current) {
      this.stats.dropped++;
      return;
    }
    const stillValid = () => {
      try {
        return this.deps.store.isCurrent(d.user, d.tokenHash, d.ts, n.category);
      } catch {
        return false;
      }
    };
    this.stats.attempted++;
    let result: PushResult;
    try {
      result = await sender.send(d, n, stillValid);
    } catch (e) {
      log.warn('push send threw', { err: errCode(e) });
      result = { retry: true };
    }
    const fields = {
      user: short(d.user),
      category: n.category,
      count: n.count,
      platform: d.platform,
      app: d.app,
      device: short(d.tokenHash),
      attempt: job.attempt,
    };
    if (result === 'cancelled') {
      this.stats.dropped++;
    } else if (result === 'ok') {
      this.stats.delivered++;
      log.info('push delivered', fields);
    } else if (result === 'invalid-token') {
      this.stats.invalidTokens++;
      this.buckets.delete(d.tokenHash);
      let removed = false;
      try {
        removed = this.deps.store.removeRegistration(d.user, d.tokenHash, d.ts);
      } catch (e) {
        log.error('registration removal failed', { err: e as Error });
      }
      log.info('push token invalid; registration removed', { ...fields, removed });
      if (removed) this.deps.onRegistrationsChanged();
    } else if (
      isRetry(result) &&
      job.attempt < MAX_RETRIES &&
      !this.stopped &&
      this.now() + this.retryDelay(result, job.attempt) <= job.expiresAt &&
      this.queue.length + this.running + this.retryTimers.size < (this.deps.queueMax ?? 10_000)
    ) {
      // Never retry earlier than the provider asked; if that's past the job's
      // lifetime (or the budget is full) the push is dropped instead.
      this.stats.retried++;
      const delay = this.retryDelay(result, job.attempt);
      const t = setTimeout(() => {
        this.retryTimers.delete(t);
        this.enqueue({ ...job, attempt: job.attempt + 1 });
      }, delay);
      t.unref();
      this.retryTimers.add(t);
      log.info('push deferred for retry', { ...fields, delay_ms: Math.round(delay) });
    } else {
      this.stats.failed++;
      log.warn('push failed', fields);
    }
  }

  /** Exponential backoff (from 60 s for quota errors), never shorter than the provider's Retry-After. */
  private readonly jitter = new WeakMap<object, number>();
  private retryDelay(r: { afterMs?: number; quota?: boolean }, attempt: number): number {
    let j = this.jitter.get(r);
    if (j === undefined) this.jitter.set(r, (j = Math.random()));
    const base = (r.quota ? 60_000 : 2_000) * 2 ** attempt;
    return Math.max(r.afterMs ?? 0, base + j * base);
  }

  /** Stop accepting work, drop timers, and wait for in-flight sends (graceful shutdown). */
  async drain(timeoutMs = 10_000): Promise<void> {
    this.stopped = true;
    for (const w of this.windows.values()) clearTimeout(w.timer);
    this.windows.clear();
    for (const t of this.retryTimers) clearTimeout(t);
    this.retryTimers.clear();
    if (this.running === 0 && this.queue.length === 0) return;
    await Promise.race([
      new Promise<void>((r) => this.idleWaiters.push(r)),
      new Promise<void>((r) => setTimeout(r, timeoutMs).unref()),
    ]);
  }

  /** Bound memory: forget buckets that have fully refilled. */
  pruneBuckets(): void {
    const t = this.now();
    for (const [k, b] of this.buckets) if (t - b.at > 3_600_000) this.buckets.delete(k);
  }
}
