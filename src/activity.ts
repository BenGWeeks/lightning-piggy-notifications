// Aggregate activity counters. Instead of one `info` line per matched event or
// delivered push (which would form a per-user timeline), the watcher counts
// outcomes per category and logs the totals once per interval. The line has
// no user, device or event fields.

import { log } from './log.js';
import type { Category } from './registration.js';

export type PushMetric = 'matched' | 'delivered' | 'failed' | 'invalid_tokens' | 'retried' | 'dropped' | 'rate_limited';
export type RegistrationOutcome =
  | 'registered'
  | 'updated'
  | 'unregistered'
  | 'stale'
  | 'limit'
  | 'invalid_token'
  | 'rejected';

export class Activity {
  private push = new Map<PushMetric, Partial<Record<Category, number>>>();
  private regs: Partial<Record<RegistrationOutcome, number>> = {};
  private since = Date.now();

  count(metric: PushMetric, category: Category): void {
    const m = this.push.get(metric) ?? {};
    m[category] = (m[category] ?? 0) + 1;
    this.push.set(metric, m);
  }

  registration(outcome: RegistrationOutcome): void {
    this.regs[outcome] = (this.regs[outcome] ?? 0) + 1;
  }

  /** Current window's totals (only non-zero entries). */
  snapshot(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [k, v] of this.push) out[k] = v;
    if (Object.keys(this.regs).length) out.registrations = this.regs;
    return out;
  }

  /** Log and reset the window. Quiet windows log nothing. */
  flush(): void {
    const snap = this.snapshot();
    const windowSec = Math.round((Date.now() - this.since) / 1000);
    this.push = new Map();
    this.regs = {};
    this.since = Date.now();
    if (Object.keys(snap).length) log.info('activity', { window_sec: windowSec, ...snap });
  }
}
